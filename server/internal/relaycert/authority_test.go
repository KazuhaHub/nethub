package relaycert

import (
	"bytes"
	"testing"
	"time"
)

func TestAuthorityIdentityChecksKeyWithoutIssuance(t *testing.T) {
	now := time.Now()
	a, err := Create("relay.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Create("relay.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(a.CAKey)
	id, err := AuthorityIdentity(a.CA, a.CAKey)
	if err != nil || len(id) != 64 {
		t.Fatal("valid authority identity refused")
	}
	for _, value := range [][2][]byte{{a.CA, b.CAKey}, {a.Certificate, a.Key}, {append(bytes.Clone(a.CA), a.CA...), a.CAKey}, {a.CA, []byte("invalid")}} {
		if _, err := AuthorityIdentity(value[0], value[1]); err == nil {
			t.Fatal("unbound authority accepted")
		}
	}
	if !bytes.Equal(a.CAKey, before) {
		t.Fatal("identity inspection mutated the key")
	}
}
