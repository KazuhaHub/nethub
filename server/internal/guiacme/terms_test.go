package guiacme

import (
	"context"
	"strings"
	"testing"
)

func TestTermsReferenceIsBoundedComparisonOnlyMetadata(t *testing.T) {
	for _, value := range []string{"https://terms.example.test/current", "data:text/plain,Do%20what%20thou%20wilt"} {
		if !validTermsReference(value) {
			t.Fatal("valid bounded terms reference rejected")
		}
	}
	for _, value := range []string{"http://terms.example.test/current", "javascript:alert(1)", "file:///terms",
		"data:text/html,%3Cscript%3E", "data:text/plain;base64,QQ==", "data:text/plain,%0Ahidden", "data:text/plain,%3Cb%3E",
		"data:text/plain,", "data:text/plain,raw space", "data:text/plain,%41", "data:text/plain," + strings.Repeat("a", 2048)} {
		if validTermsReference(value) {
			t.Fatal("unsafe or ambiguous terms reference accepted")
		}
	}
}

func TestInlinePlainTextTermsStillRequireExactCurrentConsent(t *testing.T) {
	f, config := fixture(t)
	f.terms = "data:text/plain,Do%20what%20thou%20wilt"
	client, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, registration := range []Registration{{}, {AllowCreate: true}, {AllowCreate: true, AcceptedTermsURL: "data:text/plain,Old%20terms"}} {
		if _, err := client.EnsureAccount(context.Background(), registration); err != ErrConsent {
			t.Fatal("inline terms bypassed explicit current consent")
		}
	}
	if f.counts().creates != 0 {
		t.Fatal("inline terms were automatically agreed")
	}
	if _, err := client.EnsureAccount(context.Background(), Registration{AllowCreate: true, AcceptedTermsURL: f.terms}); err != nil || f.counts().creates != 1 {
		t.Fatalf("exact inline consent: %v", err)
	}
}
