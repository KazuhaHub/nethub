package setup

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestManualGUIPublisherRequiresExactTXT(t *testing.T) {
	const name = "_acme-challenge.router.example.test."
	const value = "current-proof"
	for _, test := range []struct {
		label                string
		records              []string
		err                  error
		visible, add, failed bool
	}{
		{label: "exact", records: []string{"old-proof", value}, visible: true},
		{label: "wrong", records: []string{"old-proof"}, add: true},
		{label: "not found", err: &net.DNSError{IsNotFound: true}, add: true},
		{label: "resolver failed", err: errors.New("lookup failed"), failed: true},
	} {
		t.Run(test.label, func(t *testing.T) {
			var instruction GUIIssuerTXT
			p := manualGUIPublisher{
				lookup: func(ctx context.Context, got string) ([]string, error) {
					if _, ok := ctx.Deadline(); !ok || got != name {
						t.Fatal("lookup lacked the exact name or deadline")
					}
					return test.records, test.err
				},
				record: func(got GUIIssuerTXT) { instruction = got },
			}
			visible, err := p.PublishTXT(context.Background(), name, value, "job", time.Now().Add(time.Minute))
			if visible != test.visible || (err != nil) != test.failed {
				t.Fatalf("visible %t, error %v", visible, err)
			}
			want := GUIIssuerTXT{}
			if test.add {
				want = GUIIssuerTXT{Name: name, Value: value, Action: "add"}
			}
			if instruction != want {
				t.Fatal("unexpected TXT instruction")
			}
			if err := p.RemoveTXT(context.Background(), name, value, "job"); err != nil ||
				instruction != (GUIIssuerTXT{Name: name, Value: value, Action: "remove"}) {
				t.Fatal("missing exact cleanup instruction")
			}
		})
	}
}
