package relaystate

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func countedProxy(in, out any) map[string]any {
	value := proxy()
	value["todayTrafficIn"], value["todayTrafficOut"] = in, out
	return value
}

func TestTrafficCountersDoNotChangeObservationAdmission(t *testing.T) {
	for _, test := range []struct {
		name  string
		value any
	}{{"negative", -1}, {"fraction", 1.5}, {"overflow", json.Number("9223372036854775808")},
		{"string", "10"}, {"null", nil}, {"exponent", json.Number("1e3")}} {
		t.Run(test.name, func(t *testing.T) {
			value, err := parseSnapshot(bytes.NewReader(payload(t, countedProxy(test.value, 12))))
			if err != nil || len(value.observations) != 1 || len(value.routes) != 1 || value.trafficError != ErrTrafficResponse || value.traffic != nil {
				t.Fatal("bad optional counters changed authoritative route parsing or produced partial traffic")
			}
		})
	}
	valid, err := parseSnapshot(bytes.NewReader(payload(t, countedProxy(int64(math.MaxInt64), 0))))
	if err != nil || valid.trafficError != nil || len(valid.traffic) != 1 || valid.traffic[0].InBytes != math.MaxInt64 || valid.traffic[0].Subdomain != "abcd1234" {
		t.Fatal("exact int64 boundary or assignment was lost")
	}
	offline := countedProxy(123, 456)
	offline["status"], offline["conf"] = "offline", nil
	value, err := parseSnapshot(bytes.NewReader(payload(t, offline)))
	if err != nil || len(value.observations) != 0 || len(value.routes) != 0 || value.trafficError != nil || len(value.traffic) != 1 || value.traffic[0].Subdomain != "" {
		t.Fatal("offline counters refreshed liveness or guessed a missing assignment")
	}
	invalid := countedProxy(1, 2)
	invalid["conf"].(map[string]any)["customDomains"] = []string{"unassigned.example"}
	if _, err := parseSnapshot(bytes.NewReader(payload(t, invalid))); err != ErrResponse {
		t.Fatal("traffic support weakened route configuration checks")
	}
}

func TestTrafficQueueRetainsOnlyLatestPendingSnapshot(t *testing.T) {
	worker := &trafficWorker{queue: make(chan trafficBatch, 1)}
	for index := range 100 {
		worker.offer(trafficBatch{at: time.Unix(int64(index), 0)})
	}
	if len(worker.queue) != 1 || (<-worker.queue).at.Unix() != 99 {
		t.Fatal("telemetry backpressure retained old snapshots or an unbounded backlog")
	}
}

type trafficRepositoryStub struct {
	observations atomic.Int32
	started      chan struct{}
	observed     chan struct{}
}

func (s *trafficRepositoryStub) Observe(context.Context, []Observation) error {
	s.observations.Add(1)
	select {
	case s.observed <- struct{}{}:
	default:
	}
	return nil
}

func (s *trafficRepositoryStub) ObserveTraffic(ctx context.Context, _ time.Time, _ []TrafficSample) error {
	select {
	case s.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestBlockedTrafficWriterDoesNotBlockObservationsOrShutdown(t *testing.T) {
	data := payload(t, countedProxy(10, 20))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	defer server.Close()
	repository := &trafficRepositoryStub{started: make(chan struct{}, 1), observed: make(chan struct{}, 1)}
	poller := newPoller(t, server.URL, repository, io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); poller.Run(ctx) }()
	select {
	case <-repository.started:
	case <-time.After(time.Second):
		t.Fatal("traffic worker did not receive the initial real HTTP snapshot")
	}
	// Offering telemetry precedes Observe, so the blocked writer's signal alone
	// does not establish that the initial observation has finished.
	select {
	case <-repository.observed:
	case <-time.After(time.Second):
		t.Fatal("initial observation did not complete while telemetry was blocked")
	}
	work, stop := context.WithTimeout(ctx, time.Second)
	if err := poller.Poll(work); err != nil || repository.observations.Load() < 2 {
		stop()
		t.Fatal("blocked telemetry delayed the separate observation write")
	}
	stop()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("traffic worker did not cancel with the poller")
	}
}
