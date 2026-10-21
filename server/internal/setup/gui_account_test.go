package setup

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/guiacme"
)

type accountOperationFixture struct {
	calls     []string
	backupErr error
	create    bool
	terms     string
}

func (f *accountOperationFixture) Initialize(context.Context) error {
	f.calls = append(f.calls, "initialize")
	return nil
}
func (f *accountOperationFixture) Backup(context.Context, string) error {
	f.calls = append(f.calls, "backup")
	return nil
}
func (f *accountOperationFixture) VerifyBackup(context.Context, string) error {
	f.calls = append(f.calls, "verify")
	return f.backupErr
}
func (f *accountOperationFixture) Restore(context.Context, string) error {
	f.calls = append(f.calls, "restore")
	return nil
}
func (f *accountOperationFixture) CurrentTerms(context.Context) (string, error) {
	f.calls = append(f.calls, "terms")
	return "https://terms.example.test/current", nil
}
func (f *accountOperationFixture) EnsureAccount(_ context.Context, create bool, terms string) (guiacme.Account, error) {
	f.calls = append(f.calls, "account")
	f.create = create
	f.terms = terms
	return guiacme.Account{}, nil
}

func TestAccountCommandRequiresBackupBeforeExplicitRegistration(t *testing.T) {
	o := GUIAccountOptions{Directory: "deployment", ConfigFile: "policy", Action: "register", BackupDirectory: "backup", TermsFile: "terms", AllowCreate: true}
	f := &accountOperationFixture{backupErr: guiacme.ErrState}
	if _, err := runGUIAccountAction(context.Background(), f, o, "accepted"); err != guiacme.ErrState || !reflect.DeepEqual(f.calls, []string{"verify"}) {
		t.Fatal("registration preceded verified backup", err)
	}
	f = &accountOperationFixture{}
	r, err := runGUIAccountAction(context.Background(), f, o, "accepted")
	if err != nil || r.State != "registered" || !reflect.DeepEqual(f.calls, []string{"verify", "account"}) || !f.create || f.terms != "accepted" {
		t.Fatal("explicit registration contract", err)
	}
	for _, change := range []func(*GUIAccountOptions){func(v *GUIAccountOptions) { v.AllowCreate = false }, func(v *GUIAccountOptions) { v.TermsFile = "" }, func(v *GUIAccountOptions) { v.BackupDirectory = "" }} {
		bad := o
		change(&bad)
		f = &accountOperationFixture{}
		if _, err := runGUIAccountAction(context.Background(), f, bad, ""); err != ErrGUIAccount || len(f.calls) != 0 {
			t.Fatal("incomplete consent touched account", err)
		}
	}
}

func TestOrdinaryAccountCommandsCannotInitializeOrCreateImplicitly(t *testing.T) {
	for _, action := range []string{"initialize", "backup", "verify-backup", "restore", "terms", "lookup"} {
		t.Run(action, func(t *testing.T) {
			o := GUIAccountOptions{Directory: "deployment", ConfigFile: "policy", Action: action}
			if action == "backup" || action == "verify-backup" || action == "restore" {
				o.BackupDirectory = "backup"
			}
			f := &accountOperationFixture{}
			result, err := runGUIAccountAction(context.Background(), f, o, "")
			if err != nil || result.State == "" || len(f.calls) != 1 || f.create {
				t.Fatal("ordinary account action", err)
			}
			if action != "initialize" && f.calls[0] == "initialize" {
				t.Fatal("implicit initialization")
			}
			if action == "terms" && (result.TermsReference == nil || *result.TermsReference != "https://terms.example.test/current") {
				t.Fatal("terms review missing")
			}
			o.AllowCreate = true
			f = &accountOperationFixture{}
			if _, err := runGUIAccountAction(context.Background(), f, o, ""); err != ErrGUIAccount || len(f.calls) != 0 {
				t.Fatal("ordinary action accepted creation opt-in", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &accountOperationFixture{}
	if _, err := runGUIAccountAction(ctx, f, GUIAccountOptions{Directory: "deployment", ConfigFile: "policy", Action: "initialize"}, ""); !errors.Is(err, ErrGUIAccount) || len(f.calls) != 0 {
		t.Fatal("cancelled account action executed")
	}
}

func TestAccountConsentIsOneExactStringField(t *testing.T) {
	for _, value := range []string{`{"accepted_terms_reference":""}`, `{"accepted_terms_reference":"https://terms.example.test/current"}`} {
		if _, err := decodeGUIAccountConsent([]byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{`null`, `{}`, `{"accepted_terms_reference":null}`, `{"accepted_terms_reference":true}`, `{"accepted_terms_reference":"old","accepted_terms_reference":"new"}`, `{"accepted_terms_reference":"ok","extra":true}`} {
		if _, err := decodeGUIAccountConsent([]byte(value)); err != ErrGUIAccount {
			t.Fatal("ambiguous consent accepted")
		}
	}
}
