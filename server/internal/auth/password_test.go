package auth

import (
	"strings"
	"testing"
)

func TestPasswordSaltFormatAndVerification(t *testing.T) {
	password := "a long Unicode passphrase 密码 with spaces"
	first, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	second, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !strings.HasPrefix(first, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatal("password salts or encoded parameters are incorrect")
	}
	if valid, err := VerifyPassword(first, password); err != nil || !valid {
		t.Fatalf("correct password: valid=%v err=%v", valid, err)
	}
	if valid, err := VerifyPassword(first, password+"!"); err != nil || valid {
		t.Fatalf("wrong password: valid=%v err=%v", valid, err)
	}
	for _, invalid := range []string{
		"", strings.Repeat("x", 300), strings.Replace(first, "v=19", "v=16", 1),
		strings.Replace(first, "m=19456", "m=4294967295", 1),
		strings.Replace(first, "m=19456", "m=1", 1),
		strings.Replace(first, "t=2", "t=0", 1), strings.Replace(first, "t=2", "t=999999999", 1),
		strings.Replace(first, "p=1", "p=256", 1), strings.Replace(first, "t=2,p=1", "p=1,t=2", 1),
		strings.Replace(first, "m=19456", "m=019456", 1), first + "$extra",
		first[:len(first)-1] + "=",
	} {
		if valid, err := VerifyPassword(invalid, password); err == nil || valid {
			t.Fatalf("accepted malformed or unbounded hash %q", invalid)
		}
	}
	for _, invalid := range []string{"", strings.Repeat("x", MaxPasswordBytes+1)} {
		if _, err := HashPassword(invalid); err == nil {
			t.Fatal("accepted unsupported password length")
		}
		if valid, err := VerifyPassword(first, invalid); err == nil || valid {
			t.Fatal("verified unsupported password length")
		}
	}
}

func TestNormalizeEmail(t *testing.T) {
	if actual, err := NormalizeEmail(" Admin@Example.COM "); err != nil || actual != "admin@example.com" {
		t.Fatalf("email=%q err=%v", actual, err)
	}
	for _, email := range []string{"", "Admin <admin@example.com>", "admin@example.com\r\nInjected: yes", "not an address", strings.Repeat("x", 321) + "@example.com"} {
		if _, err := NormalizeEmail(email); err == nil {
			t.Fatalf("accepted invalid email %q", email)
		}
	}
}
