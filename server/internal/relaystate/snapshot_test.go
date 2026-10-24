package relaystate

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSnapshotRetainsUnknownRoutesWithoutRefreshingDeviceOrLeakingNames(t *testing.T) {
	const privateName = "private-unassigned-proxy-name"
	value, err := parseSnapshot(bytes.NewReader(payload(t, proxy(),
		map[string]any{"name": privateName, "status": "online", "conf": nil},
		map[string]any{"name": "offline-route", "status": "offline", "conf": nil})))
	if err != nil || len(value.observations) != 1 || len(value.routes) != 2 {
		t.Fatalf("unknown route was lost or treated as a device: %v", err)
	}
	if value.routes[0].DeviceID != deviceID || value.routes[0].Subdomain != "abcd1234" ||
		value.routes[1].DeviceID != "" || value.routes[1].Subdomain != "" {
		t.Fatal("route classification guessed an unknown device assignment")
	}
	for _, route := range value.routes {
		if !route.Valid() {
			t.Fatal("invalid bounded route")
		}
	}
	encoded, err := json.Marshal(value.routes)
	if err != nil || strings.Contains(string(encoded), privateName) {
		t.Fatal("unknown route name escaped the parser")
	}
	legacy, err := parse(bytes.NewReader(payload(t, proxy(),
		map[string]any{"name": privateName, "status": "online", "conf": nil})))
	if err != nil || len(legacy) != 1 || legacy[0] != value.observations[0] {
		t.Fatal("anomaly discovery changed display observation admission")
	}
}

func TestSnapshotKeepsDifferentAssignmentsAsDifferentEvidence(t *testing.T) {
	first, err := parseSnapshot(bytes.NewReader(payload(t, proxy())))
	if err != nil {
		t.Fatal(err)
	}
	changed := proxy()
	changed["conf"].(map[string]any)["subdomain"] = "zzzz9999"
	second, err := parseSnapshot(bytes.NewReader(payload(t, changed)))
	if err != nil || len(second.routes) != 1 || second.routes[0].DeviceID != deviceID ||
		second.routes[0].Subdomain != "zzzz9999" || second.routes[0].ProxyKey == first.routes[0].ProxyKey {
		t.Fatal("different route assignments could share one confirmation streak")
	}
	repeated, err := parseSnapshot(bytes.NewReader(payload(t, changed)))
	if err != nil || repeated.routes[0] != second.routes[0] {
		t.Fatal("identical route did not preserve its confirmation key")
	}
}

func TestSnapshotRejectsMalformedKnownRouteWithoutPartialConfirmation(t *testing.T) {
	changed := proxy()
	changed["conf"].(map[string]any)["customDomains"] = []string{"not-an-assigned-domain.example"}
	value, err := parseSnapshot(bytes.NewReader(payload(t,
		map[string]any{"name": "unknown-first", "status": "online", "conf": nil}, changed)))
	if err != ErrResponse || len(value.routes) != 0 || len(value.observations) != 0 {
		t.Fatal("malformed snapshot produced partial anomaly evidence")
	}
	for _, route := range []ObservedRoute{
		{ProxyKey: "raw-route-name"},
		{DeviceID: deviceID, ProxyKey: strings.Repeat("a", 64)},
		{Subdomain: "abcd1234", ProxyKey: strings.Repeat("a", 64)},
		{DeviceID: deviceID, Subdomain: "wrong.domain.example", ProxyKey: strings.Repeat("a", 64)},
	} {
		if route.Valid() {
			t.Fatal("malformed route accepted for database classification")
		}
	}
}
