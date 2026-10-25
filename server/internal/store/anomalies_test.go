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

func TestAnomalyConfirmationCannotSelectAnUnobservedIdentity(t *testing.T) {
	known := relaystate.Anomaly{Kind: relaystate.DomainMismatch,
		TenantID: "11111111-1111-4111-8111-111111111111", DeviceID: "22222222-2222-4222-8222-222222222222", ProxyKey: strings.Repeat("a", 64)}
	valid := relaystate.AnomalyConfirmation{Anomaly: known, Token: 1}
	if validateConfirmations([]relaystate.Anomaly{known}, []relaystate.AnomalyConfirmation{valid}) != nil {
		t.Fatal("valid observed confirmation rejected")
	}
	foreign := valid
	foreign.TenantID = "33333333-3333-4333-8333-333333333333"
	zero := valid
	zero.Token = 0
	for _, batch := range [][]relaystate.AnomalyConfirmation{{foreign}, {zero}, {valid, valid}} {
		if validateConfirmations([]relaystate.Anomaly{known}, batch) != relaystate.ErrAnomalySample {
			t.Fatal("confirmation selected an ambiguous or unobserved identity")
		}
	}
	if sameAnomalies([]relaystate.Anomaly{known, foreign.Anomaly}, []relaystate.Anomaly{known, known}) {
		t.Fatal("duplicate current finding hid a missing classification")
	}
}
