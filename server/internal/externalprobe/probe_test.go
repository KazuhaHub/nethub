package externalprobe

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fixture(t *testing.T, change func(string, map[string]any)) (*http.Client, *int) {
	t.Helper()
	calls := new(int)
	current := ""
	nodes := map[string]any{"us1.node.check-host.net": []any{}, "de1.node.check-host.net": []any{}, "ch1.node.check-host.net": []any{}}
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		*calls++
		if r.Method != "GET" || r.URL.Scheme != "https" || r.URL.Host != "check-host.net" || r.Header.Get("Accept") != "application/json" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Fatal("unexpected outbound request or credentials")
		}
		var value map[string]any
		if r.URL.Path == "/check-tcp" {
			if len(r.URL.Query()) != 2 || r.URL.Query().Get("max_nodes") != "3" {
				t.Fatal("unexpected probe options")
			}
			current = r.URL.Query().Get("host")
			value = map[string]any{"ok": 1, "request_id": "abcdef", "nodes": nodes}
		} else {
			if r.URL.Path != "/check-result-extended/abcdef" || r.URL.RawQuery != "" {
				t.Fatal("provider response controlled the outbound URL")
			}
			results := map[string]any{}
			for name := range nodes {
				results[name] = []any{map[string]any{"address": "203.0.113.10", "time": .025}}
			}
			value = map[string]any{"command": "tcp", "created": int64(1700000000), "host": current, "results": results}
		}
		if change != nil {
			change(r.URL.Path, value)
		}
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw))), Header: http.Header{}}, nil
	})}
	return client, calls
}

func TestThreeExternalPorts(t *testing.T) {
	client, calls := fixture(t, nil)
	result, err := check(context.Background(), netip.MustParseAddr("203.0.113.10"), client,
		func() time.Time { return time.Unix(1700000000, 0) }, func(context.Context) error { t.Fatal("unexpected pending probe"); return nil })
	if err != nil || len(result) != 3 || *calls != 6 {
		t.Fatal("three independent port checks failed", err, result, *calls)
	}
	for i, port := range []uint16{443, 7000, 8443} {
		if result[i] != (Port{Number: port, Nodes: 3}) {
			t.Fatal("wrong port or observer count", result)
		}
	}
}

func TestExternalFailuresCannotBecomePartialSuccess(t *testing.T) {
	for name, mutate := range map[string]func(string, map[string]any){
		"wrong target": func(path string, v map[string]any) {
			if path != "/check-tcp" {
				v["host"] = "203.0.113.10:22"
			}
		},
		"old report": func(path string, v map[string]any) {
			if path != "/check-tcp" {
				v["created"] = 1699999800
			}
		},
		"future report": func(path string, v map[string]any) {
			if path != "/check-tcp" {
				v["created"] = 1700000200
			}
		},
		"wrong command": func(path string, v map[string]any) {
			if path != "/check-tcp" {
				v["command"] = "ping"
			}
		},
		"unsafe request id": func(path string, v map[string]any) {
			if path == "/check-tcp" {
				v["request_id"] = "../private?token=secret"
			}
		},
		"missing observer": func(path string, v map[string]any) {
			if path == "/check-tcp" {
				delete(v["nodes"].(map[string]any), "ch1.node.check-host.net")
			}
		},
		"missing result": func(path string, v map[string]any) {
			if path != "/check-tcp" {
				delete(v["results"].(map[string]any), "ch1.node.check-host.net")
			}
		},
		"foreign result": func(path string, v map[string]any) {
			if path != "/check-tcp" {
				r := v["results"].(map[string]any)
				r["foreign.node.check-host.net"] = r["ch1.node.check-host.net"]
				delete(r, "ch1.node.check-host.net")
			}
		},
		"wrong peer": func(path string, v map[string]any) {
			if path != "/check-tcp" {
				v["results"].(map[string]any)["ch1.node.check-host.net"] = []any{map[string]any{"address": "203.0.113.11", "time": .01}}
			}
		},
		"missing timing": func(path string, v map[string]any) {
			if path != "/check-tcp" {
				v["results"].(map[string]any)["ch1.node.check-host.net"] = []any{map[string]any{"address": "203.0.113.10"}}
			}
		},
		"negative timing": func(path string, v map[string]any) {
			if path != "/check-tcp" {
				v["results"].(map[string]any)["ch1.node.check-host.net"] = []any{map[string]any{"address": "203.0.113.10", "time": -1}}
			}
		},
		"closed port": func(path string, v map[string]any) {
			if path != "/check-tcp" {
				v["results"].(map[string]any)["ch1.node.check-host.net"] = []any{map[string]any{"error": "secret provider error"}}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			client, _ := fixture(t, mutate)
			result, err := check(context.Background(), netip.MustParseAddr("203.0.113.10"), client, func() time.Time { return time.Unix(1700000000, 0) }, func(context.Context) error { return nil })
			if err == nil || result != nil || strings.Contains(err.Error(), "secret") {
				t.Fatal("invalid provider result or raw error accepted", result, err)
			}
		})
	}
}

func TestExternalPendingAndCancellation(t *testing.T) {
	client, calls := fixture(t, func(path string, v map[string]any) {
		if path != "/check-tcp" {
			v["results"].(map[string]any)["ch1.node.check-host.net"] = nil
		}
	})
	result, err := check(context.Background(), netip.MustParseAddr("203.0.113.10"), client, func() time.Time { return time.Unix(1700000000, 0) }, func(context.Context) error { return context.Canceled })
	if result != nil || err == nil || *calls != 2 {
		t.Fatal("pending cancellation retried or accepted", *calls, err)
	}
	client, calls = fixture(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = check(ctx, netip.MustParseAddr("203.0.113.10"), client, time.Now, pause)
	if err == nil || *calls != 0 {
		t.Fatal("canceled command sent a request")
	}
}

func TestPrivateTargetsAndUnavailableService(t *testing.T) {
	client, calls := fixture(t, nil)
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "::1", "fc00::1", "::ffff:127.0.0.1", "fe80::1%eth0", "0.0.0.0"} {
		if _, err := check(context.Background(), netip.MustParseAddr(raw), client, time.Now, pause); err == nil {
			t.Fatal("private target accepted", raw)
		}
	}
	if *calls != 0 {
		t.Fatal("private address sent to provider")
	}
	client.Transport = transportFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("secret transport error") })
	_, err := check(context.Background(), netip.MustParseAddr("203.0.113.10"), client, time.Now, pause)
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("transport error leaked or accepted", err)
	}
}

func TestPendingObservationsFinishWithoutResubmission(t *testing.T) {
	polls, submissions, waits := 0, 0, 0
	client, _ := fixture(t, func(path string, value map[string]any) {
		if path == "/check-tcp" {
			submissions++
			return
		}
		polls++
		if polls == 1 {
			value["results"].(map[string]any)["ch1.node.check-host.net"] = nil
		}
	})
	result, err := check(context.Background(), netip.MustParseAddr("203.0.113.10"), client,
		func() time.Time { return time.Unix(1700000000, 0) },
		func(context.Context) error { waits++; return nil })
	if err != nil || len(result) != 3 || submissions != 3 || polls != 4 || waits != 1 {
		t.Fatal("pending results resubmitted or lost their bound", result, err, submissions, polls, waits)
	}
}

func TestIPv6AndMappedIPv4Targets(t *testing.T) {
	for _, address := range []string{"2001:db8::10", "::ffff:203.0.113.10"} {
		t.Run(address, func(t *testing.T) {
			expected := netip.MustParseAddr(address).Unmap()
			client, _ := fixture(t, func(path string, value map[string]any) {
				if path != "/check-tcp" {
					for name := range value["results"].(map[string]any) {
						value["results"].(map[string]any)[name] = []any{map[string]any{"address": expected.String(), "time": .01}}
					}
				}
			})
			result, err := check(context.Background(), netip.MustParseAddr(address), client,
				func() time.Time { return time.Unix(1700000000, 0) }, pause)
			if err != nil || len(result) != 3 {
				t.Fatal("public address family failed", result, err)
			}
		})
	}
}

func TestPendingObservationsHaveFiniteBudget(t *testing.T) {
	client, calls := fixture(t, func(path string, value map[string]any) {
		if path != "/check-tcp" {
			value["results"].(map[string]any)["ch1.node.check-host.net"] = nil
		}
	})
	result, err := check(context.Background(), netip.MustParseAddr("203.0.113.10"), client,
		func() time.Time { return time.Unix(1700000000, 0) }, func(context.Context) error { return nil })
	if result != nil || err == nil || *calls != 31 {
		t.Fatal("unbounded pending report or repeated submission", *calls, err)
	}
}

func TestFinalPortFailureDiscardsEarlierSuccess(t *testing.T) {
	client, calls := fixture(t, func(path string, value map[string]any) {
		if path != "/check-tcp" && value["host"] == "203.0.113.10:8443" {
			value["results"].(map[string]any)["ch1.node.check-host.net"] = []any{map[string]any{"error": "secret"}}
		}
	})
	result, err := check(context.Background(), netip.MustParseAddr("203.0.113.10"), client,
		func() time.Time { return time.Unix(1700000000, 0) }, pause)
	if result != nil || err == nil || *calls != 6 || strings.Contains(err.Error(), "secret") {
		t.Fatal("partial ports were accepted or provider error leaked", result, err, *calls)
	}
}

func TestProviderBodiesAndRedirectsAreBounded(t *testing.T) {
	for _, body := range []string{"not json: secret", strings.Repeat(" ", 65537), "{}\n{}"} {
		client := &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
		})}
		_, err := check(context.Background(), netip.MustParseAddr("203.0.113.10"), client, time.Now, pause)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid body accepted or echoed", err)
		}
	}
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	calls := 0
	http.DefaultTransport = transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "check-host.net" {
			t.Fatal("redirect reached another authority")
		}
		return &http.Response{StatusCode: 302, Request: r, Header: http.Header{"Location": {"https://other.example/private?secret=value"}}, Body: io.NopCloser(strings.NewReader("secret"))}, nil
	})
	_, err := Check(context.Background(), netip.MustParseAddr("203.0.113.10"))
	if err == nil || calls != 1 || strings.Contains(err.Error(), "secret") {
		t.Fatal("redirect followed or raw URL leaked", calls, err)
	}
}
