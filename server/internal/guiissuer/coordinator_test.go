package guiissuer

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/guiacme"
	"github.com/KazuhaHub/nethub/server/internal/guicert"
	"github.com/KazuhaHub/nethub/server/internal/http01"
)

type memoryJobs struct {
	w         Snapshot
	p         Progress
	allows    func(string) bool
	lostPhase string
	revoked   bool
	reason    string
	finished  int
}

func cloneProgress(p Progress) Progress {
	if p.Order != nil {
		o := *p.Order
		p.Order = &o
	}
	if p.Proof != nil {
		o := *p.Proof
		p.Proof = &o
	}
	return p
}
func (s *memoryJobs) valid(w Snapshot) bool {
	return !s.revoked && sameWork(w, s.w) && w.Lease.Version == s.w.Lease.Version
}
func (s *memoryJobs) Renew(_ context.Context, w Snapshot) (Snapshot, error) {
	if !s.valid(w) {
		return Snapshot{}, ErrDatabase
	}
	s.w.Lease.Version++
	return s.w, nil
}
func (s *memoryJobs) Read(_ context.Context, w Snapshot) (Progress, error) {
	if !s.valid(w) {
		return Progress{}, ErrDatabase
	}
	return cloneProgress(s.p), nil
}
func (s *memoryJobs) Save(_ context.Context, w Snapshot, p Progress) (Snapshot, error) {
	if !s.valid(w) {
		return Snapshot{}, ErrDatabase
	}
	if _, err := EncodeProgress(p, w, s.allows); err != nil {
		return Snapshot{}, err
	}
	s.p = cloneProgress(p)
	s.w.Lease.Version++
	if p.Phase == s.lostPhase {
		s.lostPhase = ""
		return Snapshot{}, ErrDatabase
	}
	return s.w, nil
}
func (s *memoryJobs) Release(_ context.Context, w Snapshot, reason string) error {
	if !s.valid(w) {
		return ErrDatabase
	}
	s.reason = reason
	return nil
}
func (s *memoryJobs) Finish(_ context.Context, w Snapshot, _ Material) (string, error) {
	if !s.valid(w) {
		return "", ErrDatabase
	}
	s.finished++
	return "11111111-1111-1111-1111-111111111111", nil
}

type fixtureAccount struct {
	order                        guiacme.Order
	issued                       guiacme.Issued
	proof                        guiacme.HTTP01
	allows                       func(string) bool
	jobs                         *memoryJobs
	created, accepted, finalized int
	createError                  bool
}

func (a *fixtureAccount) AllowsURL(s string) bool { return a.allows(s) }
func (a *fixtureAccount) CreateOrder(context.Context, []byte, string, string) (guiacme.Order, error) {
	a.created++
	if a.jobs.p.Phase != "order_intent" {
		return guiacme.Order{}, ErrCoordinator
	}
	if a.createError {
		return guiacme.Order{}, ErrCoordinator
	}
	return a.order, nil
}
func (a *fixtureAccount) InspectOrder(_ context.Context, uri string, _ []byte, _, _ string) (guiacme.Order, error) {
	if uri != a.order.URI {
		return guiacme.Order{}, ErrCoordinator
	}
	return a.order, nil
}
func (a *fixtureAccount) PrepareHTTP01(context.Context, guiacme.Order, []byte, string) (guiacme.HTTP01, error) {
	return a.proof, nil
}
func (a *fixtureAccount) AcceptHTTP01(context.Context, guiacme.HTTP01, []byte, string) (guiacme.HTTP01, error) {
	if a.jobs.p.Phase != "validating" {
		return guiacme.HTTP01{}, ErrCoordinator
	}
	a.accepted++
	a.order.Status = "ready"
	return a.proof, nil
}
func (a *fixtureAccount) FinalizeOrder(context.Context, guiacme.Order, []byte, string, *x509.CertPool) (guiacme.Issued, error) {
	if a.jobs.p.Phase != "finalizing" {
		return guiacme.Issued{}, ErrCoordinator
	}
	a.finalized++
	return a.issued, nil
}

type memoryPublisher struct {
	jobs               *memoryJobs
	active             bool
	published, removed int
	publication        http01.Publication
}

func (p *memoryPublisher) Publish(_ context.Context, v http01.Publication) error {
	if p.jobs.p.Phase != "proof_saved" {
		return ErrCoordinator
	}
	p.active = true
	p.published++
	p.publication = v
	return nil
}
func (p *memoryPublisher) Remove(_ context.Context, host, generation string) error {
	if p.publication.Host != "" && (host != p.publication.Host || generation != p.publication.Generation) {
		return ErrCoordinator
	}
	p.active = false
	p.removed++
	return nil
}

func coordinatorFixture(t *testing.T) (*Coordinator, *memoryJobs, *fixtureAccount, *memoryPublisher) {
	t.Helper()
	w, p, chain, roots, allows, now := materialFixture(t)
	order := *p.Order
	order.Status = "pending"
	order.CertificateURL = ""
	proof := guiacme.HTTP01{Order: order, URI: "https://acme.example.test/challenge/original", Token: strings.Repeat("A", 22), KeyAuthorization: strings.Repeat("A", 22) + "." + strings.Repeat("A", 43), Status: "pending", ExpiresAt: now.Add(time.Hour)}
	s := &memoryJobs{w: w, p: Progress{Phase: "new"}, allows: allows}
	a := &fixtureAccount{order: order, proof: proof, issued: guiacme.Issued{Order: *p.Order, Chain: guicert.Chain{PEM: chain}}, allows: allows, jobs: s}
	pub := &memoryPublisher{jobs: s}
	c := &Coordinator{Store: s, Account: a, Publisher: pub, Roots: roots, Now: func() time.Time { return now }}
	return c, s, a, pub
}

func TestCoordinatorPersistsBeforeEachExternalMutation(t *testing.T) {
	c, s, a, pub := coordinatorFixture(t)
	var result StepResult
	for range 8 {
		var err error
		result, err = c.Step(context.Background(), s.w)
		if err != nil {
			t.Fatal("issuance step failed", err)
		}
		if result.State == "issued" {
			break
		}
	}
	if result.State != "issued" || a.created != 1 || a.accepted != 1 || a.finalized != 1 || s.finished != 1 || pub.active || pub.published != 1 || pub.removed != 1 {
		t.Fatal("issuance did not preserve one original order and retire proof")
	}
	if pub.publication.ExpiresAt.Sub(c.now()) != 10*time.Minute || !publicationPattern.MatchString(pub.publication.Generation) {
		t.Fatal("publication lifetime/generation not bounded")
	}
}

func TestCoordinatorRecoversLostCheckpointReplies(t *testing.T) {
	for _, phase := range []string{"order_saved", "proof_saved", "proof_live", "validating", "finalizing"} {
		t.Run(phase, func(t *testing.T) {
			c, s, a, pub := coordinatorFixture(t)
			s.lostPhase = phase
			lost := false
			issued := false
			for range 15 {
				result, err := c.Step(context.Background(), s.w)
				if err != nil {
					if lost || !errors.Is(err, ErrCoordinator) {
						t.Fatal("unexpected repeated failure")
					}
					lost = true
					continue
				}
				if result.State == "issued" {
					issued = true
					break
				}
			}
			if !lost || !issued || a.created != 1 || a.finalized != 1 || s.finished != 1 || pub.active {
				t.Fatal("recovery replaced order, repeated finalize or left proof live")
			}
		})
	}
}

func TestCoordinatorNeverBlindlyRetriesAmbiguousOrderCreation(t *testing.T) {
	for _, lostIntent := range []bool{false, true} {
		c, s, a, _ := coordinatorFixture(t)
		if lostIntent {
			s.lostPhase = "order_intent"
		} else {
			a.createError = true
		}
		_, _ = c.Step(context.Background(), s.w)
		result, err := c.Step(context.Background(), s.w)
		if err != nil || result.State != "terminal" || s.reason != "indeterminate_order" || a.created > 1 || s.finished != 0 {
			t.Fatal("ambiguous intent created another order")
		}
	}
}

func TestCoordinatorBudgetsValidatedAuthorizationWithPendingOrder(t *testing.T) {
	c, s, a, pub := coordinatorFixture(t)
	if _, err := c.Step(context.Background(), s.w); err != nil {
		t.Fatal(err)
	}
	a.proof.Complete = true
	result, err := c.Step(context.Background(), s.w)
	if err != nil || result.State != "waiting" || s.reason != "waiting" || pub.published != 0 || a.accepted != 0 {
		t.Fatal("pending order bypassed durable polling budget")
	}
}

func TestCoordinatorStopsRevokedWorkAndRetiresExpiredProof(t *testing.T) {
	c, s, a, pub := coordinatorFixture(t)
	for range 3 {
		if _, err := c.Step(context.Background(), s.w); err != nil {
			t.Fatal(err)
		}
	}
	s.revoked = true
	if _, err := c.Step(context.Background(), s.w); err != ErrCoordinator || a.accepted != 0 || a.finalized != 0 {
		t.Fatal("revocation did not fence mutation")
	}
	s.revoked = false
	now := s.p.Proof.ExpiresAt.Add(time.Second)
	c.Now = func() time.Time { return now }
	s.w.Lease.Expires = now.Add(120 * time.Second)
	result, err := c.Step(context.Background(), s.w)
	if err != nil || result.State != "terminal" || s.reason != "policy" || pub.active || pub.removed != 1 || a.accepted != 0 {
		t.Fatal("expired proof accepted or left live", err)
	}
}
