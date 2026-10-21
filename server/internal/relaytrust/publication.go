package relaytrust

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SQLRunner uses the trusted host's existing bounded local administrator socket
// adapter. Input stays on stdin, stderr is discarded and stdout is size-limited.
// Session authorization is a privilege boundary, not a sandbox for host root.
type SQLRunner func(context.Context, []byte) ([]byte, error)

type Publisher struct {
	Run        SQLRunner
	ServerName string
	Now        func() time.Time
}

func (p *Publisher) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Publisher) query(ctx context.Context, statement string) ([]byte, error) {
	if p.Run == nil || !validServerName(p.ServerName) || ctx.Err() != nil || len(statement) > 100000 {
		return nil, ErrGeneration
	}
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	prefix := "SET log_statement=none; SET log_min_duration_statement=-1; SET log_min_duration_sample=-1; SET log_statement_sample_rate=0; SET log_min_error_statement=panic; SET statement_timeout='10s'; SET lock_timeout='5s'; SET idle_in_transaction_session_timeout='10s'; SET standard_conforming_strings=on; SET SESSION AUTHORIZATION nethub_issuer;\n"
	body, err := p.Run(bounded, []byte(prefix+statement+";\n"))
	if err != nil || bounded.Err() != nil || len(body) > 131072 {
		return nil, ErrGeneration
	}
	return bytes.TrimSpace(body), nil
}

func (p *Publisher) Current(ctx context.Context) (*Generation, error) {
	body, err := p.query(ctx, "SELECT coalesce(public.read_current_relay_trust('"+p.ServerName+"'),'null'::jsonb)")
	if err != nil {
		return nil, err
	}
	if bytes.Equal(body, []byte("null")) {
		return nil, nil
	}
	return DecodeGeneration(body, p.ServerName, p.now())
}

// Publish validates public material independently before the narrow SQL CAS.
// An exact retry returns the current identity; a stale CAS or retirement blocked
// by unapplied devices fails closed. It never changes the relay's active signer.
func (p *Publisher) Publish(ctx context.Context, expected string, publicPEM string) (*Generation, error) {
	if expected != "" && !validID(expected) {
		return nil, ErrGeneration
	}
	bundle, err := Parse(publicPEM, p.now())
	if err != nil {
		return nil, err
	}
	roots, err := json.Marshal(bundle.RootFingerprints())
	if err != nil {
		return nil, ErrGeneration
	}
	previous := "NULL"
	if expected != "" {
		previous = "'" + expected + "'"
	}
	start, end := bundle.Window()
	statement := fmt.Sprintf("SELECT coalesce(public.publish_relay_trust(%s,'%s',decode('%s','hex'),'%s',convert_from(decode('%s','hex'),'UTF8')::jsonb,'%s','%s'),'null'::jsonb)",
		previous, p.ServerName, hex.EncodeToString([]byte(bundle.PEM())), bundle.Fingerprint(), hex.EncodeToString(roots), start.UTC().Format(time.RFC3339Nano), end.UTC().Format(time.RFC3339Nano))
	body, err := p.query(ctx, statement)
	if err != nil {
		return nil, err
	}
	generation, err := DecodeGeneration(body, p.ServerName, p.now())
	if err != nil || generation.Bundle().Fingerprint() != bundle.Fingerprint() || generation.Bundle().PEM() != bundle.PEM() || !strings.EqualFold(generation.ServerName, p.ServerName) {
		return nil, ErrGeneration
	}
	return generation, nil
}
