package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

type failingPasswordReader struct{}

func (failingPasswordReader) Read([]byte) (int, error) {
	return 0, errors.New("private input diagnostic")
}

func TestAdminPasswordInput(t *testing.T) {
	for _, suffix := range []string{"", "\n", "\r\n"} {
		want := "  a Unicode fixture 密码 passphrase  "
		got, err := readPasswordInput(strings.NewReader(want + suffix))
		if err != nil || string(got) != want {
			t.Fatal("password bytes or spaces were changed")
		}
	}
	for _, input := range []string{"short", strings.Repeat("x", 1025), strings.Repeat("x", 14), "a valid fixture\nsecond line", "a valid fixture\x00password", strings.Repeat("\xff", 20)} {
		if _, err := readPasswordInput(strings.NewReader(input)); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	if _, err := readPasswordInput(failingPasswordReader{}); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatal("input diagnostic leaked")
	}
}

func TestAdminRejectsMissingConfigurationAndPasswordArguments(t *testing.T) {
	for _, args := range [][]string{
		{"admin"}, {"admin", "reset"}, {"admin", "create"}, {"admin", "create", "--password", "private-fixture"},
		{"admin", "create", "--email", "invalid", "--owner-password-file", "fixture"},
		{"admin", "create", "--email", "admin@example.com", "--port", "70000", "--owner-password-file", "fixture"},
	} {
		var out, diagnostic bytes.Buffer
		if status := run(args, &out, &diagnostic); status != 2 || out.Len() != 0 || diagnostic.Len() == 0 {
			t.Fatal("invalid admin configuration accepted")
		}
		if strings.Contains(diagnostic.String(), "private-fixture") {
			t.Fatal("password argument echoed")
		}
	}
	if status := run([]string{"admin", "create", "--help"}, io.Discard, io.Discard); status != 0 {
		t.Fatal("admin help failed")
	}
}
