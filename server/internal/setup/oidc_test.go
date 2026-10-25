package setup

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestOIDCOutboundDeploymentPolicy(t *testing.T) {
	for _, mode := range []string{"bundled", "external"} {
		config := fixtureConfig(t)
		config.ProxyMode = mode
		original := config
		config.OIDCPrivateHosts = []string{"dex-one:5556", "dex-two:5556"}
		if sameConfig(original, config) {
			t.Fatal("backup identity ignored private outbound policy")
		}
		if err := Validate(config); err != nil {
			t.Fatal(err)
		}
		raw, err := composeOverride(config)
		if err != nil {
			t.Fatal(err)
		}
		var output struct {
			Services map[string]struct{ Command []string }
		}
		if err = json.Unmarshal(raw, &output); err != nil {
			t.Fatal(err)
		}
		var found []string
		for i, value := range output.Services["nethub-web"].Command {
			if value == "--oidc-private-host" {
				found = append(found, output.Services["nethub-web"].Command[i+1])
			}
		}
		if !slices.Equal(found, config.OIDCPrivateHosts) {
			t.Fatal("generated web command changed outbound policy")
		}
		serialized, _ := json.Marshal(config)
		var restored Config
		if json.Unmarshal(serialized, &restored) != nil || !sameConfig(config, restored) {
			t.Fatal("manifest lost outbound policy")
		}
	}
	for _, hosts := range [][]string{{"*.example"}, {"https://dex-one:5556"}, {"user@dex-one"}, make([]string, 17)} {
		config := fixtureConfig(t)
		config.OIDCPrivateHosts = hosts
		if Validate(config) == nil {
			t.Fatal("unsafe deployment exception accepted")
		}
	}
}
