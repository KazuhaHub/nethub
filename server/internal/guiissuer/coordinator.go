package guiissuer

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/guiacme"
	"github.com/KazuhaHub/nethub/server/internal/http01"
)

var ErrCoordinator = errors.New("certificate issuance step unavailable")

type JobStore interface {
	Renew(context.Context, Snapshot) (Snapshot, error)
	Read(context.Context, Snapshot) (Progress, error)
	Save(context.Context, Snapshot, Progress) (Snapshot, error)
	Release(context.Context, Snapshot, string) error
	Finish(context.Context, Snapshot, Material) (string, error)
}

type Account interface {
	AllowsURL(string) bool
	CreateOrder(context.Context, []byte, string, string) (guiacme.Order, error)
	InspectOrder(context.Context, string, []byte, string, string) (guiacme.Order, error)
	PrepareHTTP01(context.Context, guiacme.Order, []byte, string) (guiacme.HTTP01, error)
	AcceptHTTP01(context.Context, guiacme.HTTP01, []byte, string) (guiacme.HTTP01, error)
	FinalizeOrder(context.Context, guiacme.Order, []byte, string, *x509.CertPool) (guiacme.Issued, error)
}

type ChallengePublisher interface {
	Publish(context.Context, http01.Publication) error
	Remove(context.Context, string, string) error
}

// Coordinator advances a claimed job without initializing an account, signing
// a device request or applying a certificate. Use a SQLStore with independently
// protected domain policy and a pre-registered AccountStore. Static HTTP proofs
// additionally require independent expiry cleanup before production enablement.
type Coordinator struct {
	Store     JobStore
	Account   Account
	Publisher ChallengePublisher
	Roots     *x509.CertPool
	Now       func() time.Time
}

type StepResult struct {
	Work              Snapshot `json:"-"`
	State, Generation string   `json:"-"`
}

func (c *Coordinator) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Step performs one bounded phase. Callers stop on any error and recover through
// a new fenced claim; they never retry a stale lease or infer a successful save
// from a remote side effect. State is progressed, waiting, issued or terminal.
func (c *Coordinator) Step(ctx context.Context, original Snapshot) (StepResult, error) {
	if c.Store == nil || c.Account == nil || c.Publisher == nil || c.Roots == nil || ctx.Err() != nil {
		return StepResult{}, ErrCoordinator
	}
	ctx, cancel := context.WithTimeout(ctx, 110*time.Second)
	defer cancel()
	w := original
	fresh := func() error {
		next, err := c.Store.Renew(ctx, w)
		if err != nil || !sameWork(w, next) || next.Lease.Version != w.Lease.Version+1 || !next.Lease.Expires.After(c.now()) {
			return ErrCoordinator
		}
		w = next
		return nil
	}
	if fresh() != nil {
		return StepResult{}, ErrCoordinator
	}
	p, err := c.Store.Read(ctx, w)
	if err != nil || p.Phase != "new" && p.validate(w, c.Account.AllowsURL) != nil {
		return StepResult{}, ErrCoordinator
	}
	save := func() error {
		next, err := c.Store.Save(ctx, w, p)
		if err != nil || !sameWork(w, next) || next.Lease.Version != w.Lease.Version+1 {
			return ErrCoordinator
		}
		w = next
		return nil
	}
	result := func(state string) (StepResult, error) { return StepResult{Work: w, State: state}, nil }
	release := func(reason string) (StepResult, error) {
		if c.Store.Release(ctx, w, reason) != nil {
			return StepResult{}, ErrCoordinator
		}
		state := "terminal"
		if reason == "waiting" || reason == "transient" {
			state = "waiting"
		}
		return result(state)
	}
	failRemote := func(err error) (StepResult, error) {
		if errors.Is(err, guiacme.ErrOrder) || errors.Is(err, guiacme.ErrState) {
			return release("policy")
		}
		return release("transient")
	}
	retire := func() error {
		if p.Proof != nil && !p.Retired {
			// Exact-generation removal is safe to repeat after a lost save reply.
			if fresh() != nil || c.Publisher.Remove(ctx, w.Host, p.Generation) != nil {
				return ErrCoordinator
			}
			p.Retired = true
		}
		return nil
	}
	finalizing := func(order guiacme.Order) (StepResult, error) {
		if !sameOrderIdentity(*p.Order, order) || order.Status != "ready" && order.Status != "valid" && order.Status != "processing" {
			return release("policy")
		}
		if retire() != nil {
			return StepResult{}, ErrCoordinator
		}
		p.Order = &order
		p.Phase = "finalizing"
		if save() != nil {
			return StepResult{}, ErrCoordinator
		}
		return result("progressed")
	}
	switch p.Phase {
	case "new":
		// An intent recovered in another invocation is deliberately ambiguous.
		// Only this invocation, after its own successful save, may create once.
		p = Progress{Phase: "order_intent"}
		if save() != nil || fresh() != nil {
			return StepResult{}, ErrCoordinator
		}
		order, err := c.Account.CreateOrder(ctx, w.CSR, w.Host, w.PublicKey)
		if err != nil {
			return release("indeterminate_order")
		}
		p = Progress{Phase: "order_saved", Order: &order}
		if save() != nil {
			return StepResult{}, ErrCoordinator
		}
		return result("progressed")
	case "order_intent":
		return release("indeterminate_order")
	case "order_saved", "proof_saved", "proof_live", "validating":
		if fresh() != nil {
			return StepResult{}, ErrCoordinator
		}
		order, err := c.Account.InspectOrder(ctx, p.Order.URI, w.CSR, w.Host, w.PublicKey)
		if err != nil {
			return failRemote(err)
		}
		if !sameOrderIdentity(*p.Order, order) {
			return release("policy")
		}
		if order.Status == "ready" || order.Status == "valid" || order.Status == "processing" {
			return finalizing(order)
		}
		if order.Status != "pending" {
			return release("policy")
		}
		if p.Phase == "order_saved" {
			if fresh() != nil {
				return StepResult{}, ErrCoordinator
			}
			proof, err := c.Account.PrepareHTTP01(ctx, order, w.CSR, w.PublicKey)
			if err != nil {
				return failRemote(err)
			}
			if proof.Complete {
				return release("waiting")
			}
			proof.ExpiresAt = minTime(proof.ExpiresAt, w.Lease.Deadline, c.now().Add(10*time.Minute)).UTC()
			var generation [16]byte
			if _, err := rand.Read(generation[:]); err != nil {
				return StepResult{}, ErrCoordinator
			}
			p = Progress{Phase: "proof_saved", Order: &order, Proof: &proof, Generation: hex.EncodeToString(generation[:])}
			if save() != nil {
				return StepResult{}, ErrCoordinator
			}
			return result("progressed")
		}
		if !p.Proof.ExpiresAt.After(c.now()) {
			if retire() != nil {
				return StepResult{}, ErrCoordinator
			}
			return release("policy")
		}
		switch p.Phase {
		case "proof_saved":
			if fresh() != nil {
				return StepResult{}, ErrCoordinator
			}
			proof := p.Proof
			if c.Publisher.Publish(ctx, http01.Publication{Host: w.Host, Generation: p.Generation, Token: proof.Token, KeyAuthorization: proof.KeyAuthorization, ExpiresAt: proof.ExpiresAt}) != nil {
				return StepResult{}, ErrCoordinator
			}
			p.Phase = "proof_live"
			if save() != nil {
				return StepResult{}, ErrCoordinator
			}
			return result("progressed")
		case "proof_live":
			// Record acceptance intent first. On recovery, inspect the same order
			// and challenge rather than blindly accepting an arbitrary new one.
			p.Phase = "validating"
			if save() != nil || fresh() != nil {
				return StepResult{}, ErrCoordinator
			}
			if _, err := c.Account.AcceptHTTP01(ctx, *p.Proof, w.CSR, w.PublicKey); err != nil {
				return failRemote(err)
			}
			return result("progressed")
		default:
			// A crash may follow intent but precede the acceptance POST. The SDK
			// rechecks this exact challenge and does not POST processing/valid
			// challenges, so recovery safely covers both sides of that window.
			if fresh() != nil {
				return StepResult{}, ErrCoordinator
			}
			if _, err := c.Account.AcceptHTTP01(ctx, *p.Proof, w.CSR, w.PublicKey); err != nil {
				return failRemote(err)
			}
			return release("waiting")
		}
	case "finalizing":
		if fresh() != nil {
			return StepResult{}, ErrCoordinator
		}
		issued, err := c.Account.FinalizeOrder(ctx, *p.Order, w.CSR, w.PublicKey, c.Roots.Clone())
		if errors.Is(err, guiacme.ErrNotReady) {
			return release("waiting")
		}
		if err != nil {
			return failRemote(err)
		}
		if !sameOrderIdentity(*p.Order, issued.Order) {
			return release("policy")
		}
		p.Order = &issued.Order
		if save() != nil {
			return StepResult{}, ErrCoordinator
		}
		material, err := PrepareMaterial(w, p, issued.Chain.PEM, c.Roots.Clone(), c.Account.AllowsURL, c.now())
		if err != nil {
			return release("policy")
		}
		if fresh() != nil {
			return StepResult{}, ErrCoordinator
		}
		generation, err := c.Store.Finish(ctx, w, material)
		if err != nil {
			return StepResult{}, ErrCoordinator
		}
		return StepResult{Work: w, State: "issued", Generation: generation}, nil
	default:
		return StepResult{}, ErrCoordinator
	}
}

func minTime(values ...time.Time) time.Time {
	out := values[0]
	for _, v := range values[1:] {
		if v.Before(out) {
			out = v
		}
	}
	return out
}
