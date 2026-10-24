package store

import (
	"strings"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/relaystate"
)

func TestAnomalyRoutesRejectAmbiguousDatabaseCandidates(t *testing.T) {
	known := relaystate.ObservedRoute{DeviceID: "11111111-1111-4111-8111-111111111111",
		Subdomain: "abcd1234", ProxyKey: strings.Repeat("a", 64)}
	unknown := relaystate.ObservedRoute{ProxyKey: strings.Repeat("b", 64)}
	if validateAnomalyRoutes([]relaystate.ObservedRoute{known, unknown}) != nil || validateAnomalyRoutes(nil) != nil {
		t.Fatal("valid known/unknown snapshot rejected")
	}
	duplicateDevice := known
	duplicateDevice.ProxyKey = strings.Repeat("c", 64)
	malformed := known
	malformed.DeviceID = "not-a-device-id"
	for _, routes := range [][]relaystate.ObservedRoute{
		{known, duplicateDevice}, {unknown, unknown}, {malformed}, make([]relaystate.ObservedRoute, relaystate.MaxProxies+1),
	} {
		if validateAnomalyRoutes(routes) != relaystate.ErrAnomalySample {
			t.Fatal("ambiguous or oversized snapshot reached database classification")
		}
	}
}
