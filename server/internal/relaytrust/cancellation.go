package relaytrust

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/boundedjson"
)

// Cancellation is an immutable database decision that this operation ID may
// never begin. It is not inferred from a missing row or an unavailable query.
type Cancellation struct {
	SwitchRequest
	ServerName   string    `json:"server_name"`
	IntentDigest string    `json:"intent_sha256"`
	CancelledAt  time.Time `json:"cancelled_at"`
}

func decodeCancellation(raw []byte, name string, now time.Time) (*Cancellation, error) {
	fields, err := boundedjson.Object(bytes.NewReader(raw))
	if err != nil || len(fields) != 9 || !validServerName(name) || now.IsZero() {
		return nil, ErrGeneration
	}
	for _, key := range []string{"id", "trust_generation_id", "server_name", "previous_root", "next_root", "previous_leaf", "next_leaf", "intent_sha256", "cancelled_at"} {
		if _, ok := fields[key]; !ok {
			return nil, ErrGeneration
		}
	}
	var c Cancellation
	if json.Unmarshal(raw, &c) != nil || !c.SwitchRequest.Valid() || c.ServerName != name || !certificateFingerprint.MatchString(c.IntentDigest) || c.CancelledAt.IsZero() || c.CancelledAt.After(now.Add(5*time.Second)) {
		return nil, ErrGeneration
	}
	return &c, nil
}

func (c *Cancellation) Valid(name string, now time.Time) bool {
	if c == nil {
		return false
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return false
	}
	_, err = decodeCancellation(raw, name, now)
	return err == nil
}

// CancelSwitch serializes with BeginSwitch under the same head lock. It refuses
// every existing switch, including pending and completed operations. Exact retry
// preserves the first cancellation timestamp and original request/intent digest.
func (p *Publisher) CancelSwitch(ctx context.Context, r SwitchRequest, intent string) (*Cancellation, error) {
	if !r.Valid() || !certificateFingerprint.MatchString(intent) {
		return nil, ErrGeneration
	}
	statement := fmt.Sprintf("SELECT coalesce(public.cancel_relay_authority_switch('%s','%s','%s','%s','%s','%s','%s','%s'),'null'::jsonb)", r.ID, r.GenerationID, p.ServerName, r.PreviousRoot, r.NextRoot, r.PreviousLeaf, r.NextLeaf, intent)
	raw, err := p.query(ctx, statement)
	if err != nil {
		return nil, err
	}
	c, err := decodeCancellation(raw, p.ServerName, p.now())
	if err != nil || c.SwitchRequest != r || c.IntentDigest != intent {
		return nil, ErrGeneration
	}
	return c, nil
}

func (p *Publisher) ReadCancellation(ctx context.Context, id string) (*Cancellation, error) {
	if !validID(id) {
		return nil, ErrGeneration
	}
	raw, err := p.query(ctx, fmt.Sprintf("SELECT coalesce(public.read_relay_authority_cancellation('%s','%s'),'null'::jsonb)", id, p.ServerName))
	if err != nil {
		return nil, err
	}
	c, err := decodeCancellation(raw, p.ServerName, p.now())
	if err != nil || c.ID != id {
		return nil, ErrGeneration
	}
	return c, nil
}
