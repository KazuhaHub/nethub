package relaystate

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/relayhook"
)

var ErrTrafficResponse = errors.New("relay traffic counters unavailable")

// Empty Subdomain denotes an offline counter; storage needs a prior binding.
type TrafficSample struct {
	DeviceID  string `json:"device_id"`
	Subdomain string `json:"subdomain"`
	InBytes   int64  `json:"in_bytes"`
	OutBytes  int64  `json:"out_bytes"`
}

func (s TrafficSample) Valid() bool {
	return uuid.MatchString(s.DeviceID) && (s.Subdomain == "" || subdomain.MatchString(s.Subdomain)) && s.InBytes >= 0 && s.OutBytes >= 0
}

type TrafficRepository interface {
	ObserveTraffic(context.Context, time.Time, []TrafficSample) error
}

func parseTraffic(proxies []map[string]json.RawMessage) ([]TrafficSample, error) {
	samples := make([]TrafficSample, 0, len(proxies))
	for _, proxy := range proxies {
		name, _ := text(proxy, "name")
		id := strings.TrimSuffix(strings.TrimPrefix(name, "nethub-"), "-web")
		if !uuid.MatchString(id) || name != relayhook.ProxyName(id) {
			continue
		}
		sample := TrafficSample{DeviceID: id}
		status, _ := text(proxy, "status")
		if status == "online" {
			var configuration map[string]json.RawMessage
			if json.Unmarshal(proxy["conf"], &configuration) != nil {
				return nil, ErrTrafficResponse
			}
			sample.Subdomain, _ = text(configuration, "subdomain")
		}
		for _, field := range []struct {
			name  string
			value *int64
		}{{"todayTrafficIn", &sample.InBytes}, {"todayTrafficOut", &sample.OutBytes}} {
			data, present := proxy[field.name]
			if !present || null(data) || json.Unmarshal(data, field.value) != nil || *field.value < 0 {
				return nil, ErrTrafficResponse
			}
		}
		if !sample.Valid() {
			return nil, ErrTrafficResponse
		}
		samples = append(samples, sample)
	}
	return samples, nil
}

type trafficBatch struct {
	at      time.Time
	samples []TrafficSample
	err     error
}

type trafficWorker struct {
	repository TrafficRepository
	queue      chan trafficBatch
}

// Keep one pending snapshot; telemetry never waits in the observation path.
func (w *trafficWorker) offer(value trafficBatch) {
	select {
	case w.queue <- value:
		return
	default:
	}
	select {
	case <-w.queue:
	default:
	}
	select {
	case w.queue <- value:
	default:
	}
}

func (p *Poller) runTraffic(ctx context.Context) {
	var failed bool
	for {
		select {
		case <-ctx.Done():
			return
		case batch := <-p.traffic.queue:
			err := batch.err
			if err == nil {
				work, cancel := context.WithTimeout(ctx, 2*time.Second)
				err = p.traffic.repository.ObserveTraffic(work, batch.at, batch.samples)
				cancel()
			}
			if ctx.Err() != nil {
				return
			}
			if err != nil && !failed {
				p.logger.Warn("Relay traffic sampling unavailable")
			} else if err == nil && failed {
				p.logger.Info("Relay traffic sampling resumed")
			}
			failed = err != nil
		}
	}
}
