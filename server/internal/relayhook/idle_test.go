package relayhook

import (
	"net/http"
	"testing"
)

// The pinned frps plugin client uses http.DefaultTransport for a plain
// host:port hook address. If the hook server's idle timeout does not exceed
// that transport's, a pooled connection can be closed by the server while frps
// reuses it, and the non-replayable Ping POST fails with EOF.
func TestServerIdleTimeoutOutlastsFrpsPluginClient(t *testing.T) {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatal("default transport type changed; re-check the frps plugin client")
	}
	if transport.IdleConnTimeout <= 0 {
		t.Fatal("default transport has no idle limit; re-check the frps plugin client")
	}
	if ServerIdleTimeout < transport.IdleConnTimeout+transport.IdleConnTimeout/4 {
		t.Fatalf("hook server idle timeout %s must clearly exceed the frps client idle timeout %s",
			ServerIdleTimeout, transport.IdleConnTimeout)
	}
}
