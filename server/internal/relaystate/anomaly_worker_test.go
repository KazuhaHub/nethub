package relaystate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type anomalyRepositoryStub struct {
	inspect func(context.Context, []ObservedRoute) ([]Anomaly, error)
	commit  func(context.Context, []ObservedRoute, []Anomaly, []AnomalyConfirmation) error
	observe func(context.Context, []Observation) error
}

func (s *anomalyRepositoryStub) Observe(ctx context.Context, observations []Observation) error {
	if s.observe != nil {
		return s.observe(ctx, observations)
	}
	return nil
}

func (s *anomalyRepositoryStub) Inspect(ctx context.Context, routes []ObservedRoute) ([]Anomaly, error) {
	if s.inspect != nil {
		return s.inspect(ctx, routes)
	}
	return nil, nil
}

func (s *anomalyRepositoryStub) Commit(ctx context.Context, routes []ObservedRoute, findings []Anomaly, batch []AnomalyConfirmation) error {
	if s.commit != nil {
		return s.commit(ctx, routes, findings, batch)
	}
	return nil
}

func anomalyTestWorker(t *testing.T, repository *anomalyRepositoryStub) (*anomalyWorker, func(int)) {
	t.Helper()
	data := payload(t, proxy())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	t.Cleanup(server.Close)
	poller := newPoller(t, server.URL, repository, io.Discard)
	worker := poller.anomalies
	if worker == nil {
		t.Fatal("repository anomaly capability was not enabled")
	}
	t.Cleanup(worker.reader.client.CloseIdleConnections)
	started := time.Now()
	now := started
	worker.now = func() time.Time { return now }
	worker.tracker, _ = NewAnomalyTracker(started, 3)
	return worker, func(seconds int) { now = started.Add(time.Duration(seconds) * time.Second) }
}

func TestAnomalyWorkerAcknowledgesOnlyCommittedReceipts(t *testing.T) {
	anomaly := sampleAnomaly(DomainMismatch, "known")
	var batches []int
	failed := false
	repository := &anomalyRepositoryStub{
		inspect: func(ctx context.Context, routes []ObservedRoute) ([]Anomaly, error) {
			if len(routes) != 1 || !routes[0].Valid() || routes[0].DeviceID != deviceID {
				t.Fatal("inspector did not receive the bounded route snapshot")
			}
			return []Anomaly{anomaly}, nil
		},
		commit: func(ctx context.Context, routes []ObservedRoute, expected []Anomaly, batch []AnomalyConfirmation) error {
			if len(expected) != 1 || expected[0] != anomaly {
				t.Fatal("commit lost its expected classification")
			}
			batches = append(batches, len(batch))
			if len(batch) == 1 && !failed {
				failed = true
				return errors.New("private database diagnostic")
			}
			return nil
		},
	}
	worker, advance := anomalyTestWorker(t, repository)
	for _, seconds := range []int{15, 30, 45, 60, 75} {
		advance(seconds)
		err := worker.sample(context.Background())
		if seconds == 45 && err != ErrStorage || seconds != 45 && err != nil {
			t.Fatalf("sample %d: %v", seconds, err)
		}
	}
	want := []int{0, 0, 1, 1, 0}
	if len(batches) != len(want) {
		t.Fatal("missing persistence attempt")
	}
	for index := range want {
		if batches[index] != want[index] {
			t.Fatalf("pending receipt was lost or repeated after COMMIT: %v", batches)
		}
	}
}

func TestAnomalyWorkerRechecksChangedClassificationAndFailedLookup(t *testing.T) {
	for _, failure := range []string{"lookup", "changed"} {
		t.Run(failure, func(t *testing.T) {
			anomaly := sampleAnomaly(RevokedOnline, "known")
			inspections, commits := 0, 0
			repository := &anomalyRepositoryStub{
				inspect: func(context.Context, []ObservedRoute) ([]Anomaly, error) {
					inspections++
					if failure == "lookup" && inspections == 3 {
						return nil, errors.New("private lookup error")
					}
					return []Anomaly{anomaly}, nil
				},
				commit: func(ctx context.Context, routes []ObservedRoute, expected []Anomaly, batch []AnomalyConfirmation) error {
					commits++
					if failure == "changed" && commits == 3 {
						return ErrAnomalyChanged
					}
					if inspections > 3 && inspections < 6 && len(batch) != 0 {
						t.Fatal("failed/changed observation did not reset confirmation")
					}
					if inspections == 6 && len(batch) != 1 {
						t.Fatal("three fresh observations did not reconfirm")
					}
					return nil
				},
			}
			worker, advance := anomalyTestWorker(t, repository)
			for index := 1; index <= 6; index++ {
				advance(index * 15)
				err := worker.sample(context.Background())
				if index == 3 && err == nil || index != 3 && err != nil {
					t.Fatalf("unexpected sample outcome: %v", err)
				}
			}
		})
	}
}

func TestAnomalyInspectionHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := false
	repository := &anomalyRepositoryStub{inspect: func(ctx context.Context, routes []ObservedRoute) ([]Anomaly, error) {
		entered = true
		deadline, present := ctx.Deadline()
		if !present || time.Until(deadline) > 2*time.Second {
			t.Fatal("inspection did not receive its two-second budget")
		}
		cancel()
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	worker, advance := anomalyTestWorker(t, repository)
	advance(15)
	started := time.Now()
	if err := worker.sample(ctx); err != ErrStorage || !entered || time.Since(started) > time.Second {
		t.Fatalf("inspection cancellation was lost: %v", err)
	}
}

func TestBlockedAnomalyFetchDoesNotBlockDisplayObservation(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var requests, observations atomic.Int32
	data := payload(t, proxy())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			close(started)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	defer server.Close()
	repository := &anomalyRepositoryStub{observe: func(context.Context, []Observation) error { observations.Add(1); return nil }}
	poller := newPoller(t, server.URL, repository, io.Discard)
	defer poller.anomalies.reader.client.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- poller.anomalies.sample(ctx) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("anomaly fetch did not start")
	}
	display, stopDisplay := context.WithTimeout(ctx, time.Second)
	defer stopDisplay()
	err := poller.Poll(display)
	close(release)
	if err != nil || observations.Load() != 1 {
		t.Fatalf("anomaly HTTP connection blocked the independent display poll: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("anomaly fetch did not finish")
	}
}
