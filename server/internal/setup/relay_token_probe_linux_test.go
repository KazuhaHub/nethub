package setup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/protocol"
	"github.com/KazuhaHub/nethub/server/internal/relayprobe"
)

// This optional test is mandatory in the actual Compose relay harness, which
// verifies its PASS receipt and both original official-client controls/routes.
func TestNativeRelayTokenProbe(t *testing.T) {
	input := os.Getenv("NETHUB_TEST_TOKEN_ASSIGNMENT")
	if input == "" {
		t.Skip("actual owned Compose assignment is required")
	}
	if os.Geteuid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" ||
		!filepath.IsAbs(input) || filepath.Clean(input) != input || filepath.Base(input) != "assignment0.json" ||
		filepath.Base(filepath.Dir(input)) != "relay-test" {
		t.Fatal("fresh hosted root and owned relay assignment required")
	}
	raw, err := authorityRead(input, 0, protocol.MaxBodyBytes)
	var assignment protocol.EnrollResponse
	if err != nil || json.Unmarshal(raw, &assignment) != nil || assignment.ServerName != "console.example.com" || assignment.ServerPort != 7000 {
		t.Fatal("actual protected relay assignment unavailable")
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal("independent refusal token unavailable")
	}
	wrong := hex.EncodeToString(random[:])
	if wrong == assignment.FRPToken {
		t.Fatal("refusal token is not independent")
	}
	credential := relayprobe.LoginCredential{Token: assignment.FRPToken, DeviceID: assignment.DeviceID, DomainClaim: assignment.DomainClaim}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, accepted := range []bool{true, false, true} {
		credential.Token = assignment.FRPToken
		if !accepted {
			credential.Token = wrong
		}
		observed, err := relayprobe.LoginToken(ctx, "127.0.0.1:7000", assignment.ServerName, []byte(assignment.RelayCAPEM), credential)
		if err != nil || observed != accepted {
			t.Fatal("official relay token admission or exact token-auth refusal unconfirmed")
		}
	}
	t.Log("Official frp 0.71.1 accepted the valid token, refused an independent token at token authentication, and accepted the original token again without a proxy request")
}
