package relaytrust

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/boundedjson"
)

var certificateFingerprint = regexp.MustCompile(`^[a-f0-9]{64}$`)

// SwitchRequest must be durably journaled by the host before BeginSwitch. The
// database receipt fences admission; it does not authorize replaying host writes.
type SwitchRequest struct {
	ID           string `json:"id"`
	GenerationID string `json:"trust_generation_id"`
	PreviousRoot string `json:"previous_root"`
	NextRoot     string `json:"next_root"`
	PreviousLeaf string `json:"previous_leaf"`
	NextLeaf     string `json:"next_leaf"`
}

type Switch struct {
	SwitchRequest
	ServerName   string     `json:"server_name"`
	Phase        string     `json:"phase"`
	CreatedAt    time.Time  `json:"created_at"`
	FinishedAt   *time.Time `json:"finished_at"`
	ObservedLeaf *string    `json:"observed_leaf"`
}

// Valid rechecks a typed adapter receipt against the same identity, phase and
// timestamp rules used for bounded SQL decoding before host side effects.
func (s *Switch) Valid(serverName string, now time.Time) bool {
	if s == nil {
		return false
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return false
	}
	_, err = decodeSwitch(raw, serverName, now)
	return err == nil
}

func (r SwitchRequest) valid() bool {
	return validID(r.ID) && validID(r.GenerationID) &&
		certificateFingerprint.MatchString(r.PreviousRoot) && certificateFingerprint.MatchString(r.NextRoot) && r.PreviousRoot != r.NextRoot &&
		certificateFingerprint.MatchString(r.PreviousLeaf) && certificateFingerprint.MatchString(r.NextLeaf) && r.PreviousLeaf != r.NextLeaf
}

// Valid checks the immutable public operation identity before host journaling.
func (r SwitchRequest) Valid() bool { return r.valid() }

func decodeSwitch(data []byte, name string, now time.Time) (*Switch, error) {
	fields, err := boundedjson.Object(bytes.NewReader(data))
	if err != nil || len(fields) != 11 || !validServerName(name) || now.IsZero() {
		return nil, ErrGeneration
	}
	for _, key := range []string{"id", "trust_generation_id", "server_name", "previous_root", "next_root", "previous_leaf", "next_leaf", "phase", "created_at", "finished_at", "observed_leaf"} {
		if _, ok := fields[key]; !ok {
			return nil, ErrGeneration
		}
	}
	var s Switch
	if json.Unmarshal(data, &s) != nil || !s.SwitchRequest.valid() || s.ServerName != name || s.CreatedAt.IsZero() || s.CreatedAt.After(now.Add(5*time.Second)) {
		return nil, ErrGeneration
	}
	if s.Phase == "pending" {
		if s.FinishedAt != nil || s.ObservedLeaf != nil {
			return nil, ErrGeneration
		}
	} else {
		expected := s.NextLeaf
		if s.Phase == "rolled_back" {
			expected = s.PreviousLeaf
		} else if s.Phase != "committed" {
			return nil, ErrGeneration
		}
		if s.FinishedAt == nil || s.ObservedLeaf == nil || *s.ObservedLeaf != expected || s.FinishedAt.Before(s.CreatedAt) || s.FinishedAt.After(now.Add(5*time.Second)) {
			return nil, ErrGeneration
		}
	}
	return &s, nil
}

// BeginSwitch atomically requires current overlap acknowledgements and blocks
// enrollment/publication until a matching terminal host report. It never expires.
func (p *Publisher) BeginSwitch(ctx context.Context, r SwitchRequest) (*Switch, error) {
	if !r.valid() {
		return nil, ErrGeneration
	}
	statement := fmt.Sprintf("SELECT coalesce(public.begin_relay_authority_switch('%s','%s','%s','%s','%s','%s','%s'),'null'::jsonb)", r.ID, r.GenerationID, p.ServerName, r.PreviousRoot, r.NextRoot, r.PreviousLeaf, r.NextLeaf)
	body, err := p.query(ctx, statement)
	if err != nil {
		return nil, err
	}
	s, err := decodeSwitch(body, p.ServerName, p.now())
	if err != nil || s.SwitchRequest != r {
		return nil, ErrGeneration
	}
	return s, nil
}

func (p *Publisher) ReadSwitch(ctx context.Context, id string) (*Switch, error) {
	if !validID(id) {
		return nil, ErrGeneration
	}
	body, err := p.query(ctx, fmt.Sprintf("SELECT coalesce(public.read_relay_authority_switch('%s','%s'),'null'::jsonb)", id, p.ServerName))
	if err != nil {
		return nil, err
	}
	s, err := decodeSwitch(body, p.ServerName, p.now())
	if err != nil || s.ID != id {
		return nil, ErrGeneration
	}
	return s, nil
}

// FinishSwitch records a protected host assertion. The caller must independently
// verify the served leaf and durable host state before resolving this fence.
func (p *Publisher) FinishSwitch(ctx context.Context, r SwitchRequest, phase, observed string) (*Switch, error) {
	if !r.valid() || (phase != "committed" && phase != "rolled_back") || !certificateFingerprint.MatchString(observed) {
		return nil, ErrGeneration
	}
	expected := r.NextLeaf
	if phase == "rolled_back" {
		expected = r.PreviousLeaf
	}
	if observed != expected {
		return nil, ErrGeneration
	}
	current, err := p.ReadSwitch(ctx, r.ID)
	if err != nil || current.SwitchRequest != r {
		return nil, ErrGeneration
	}
	body, err := p.query(ctx, fmt.Sprintf("SELECT coalesce(public.finish_relay_authority_switch('%s','%s','%s'),'null'::jsonb)", r.ID, phase, observed))
	if err != nil {
		return nil, err
	}
	s, err := decodeSwitch(body, p.ServerName, p.now())
	if err != nil || s.SwitchRequest != r || s.Phase != phase || s.ObservedLeaf == nil || *s.ObservedLeaf != observed {
		return nil, ErrGeneration
	}
	return s, nil
}
