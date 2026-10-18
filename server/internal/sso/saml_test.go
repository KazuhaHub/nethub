package sso

import (
	"encoding/xml"
	"testing"

	authsaml "github.com/KazuhaHub/authcore/saml"
	crewjamsaml "github.com/crewjam/saml"
)

func samlConfig() authsaml.Config {
	return authsaml.Config{
		EntityID:    "https://console.example.com/saml/metadata",
		ACSURL:      "https://console.example.com/saml/acs",
		IDPMetadata: &crewjamsaml.EntityDescriptor{EntityID: "https://idp.example.com"},
		ReplayCache: authsaml.NewMemoryReplayCache(16),
	}
}

func TestSAMLMetadataUsesConfiguredCallback(t *testing.T) {
	provider, err := NewSAMLProvider(samlConfig())
	if err != nil {
		t.Fatal(err)
	}
	document, err := provider.MetadataXML()
	if err != nil {
		t.Fatal(err)
	}
	var metadata crewjamsaml.EntityDescriptor
	if err := xml.Unmarshal(document, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.EntityID != samlConfig().EntityID || len(metadata.SPSSODescriptors) != 1 {
		t.Fatalf("unexpected SP metadata: %s", document)
	}
	services := metadata.SPSSODescriptors[0].AssertionConsumerServices
	post := false
	for _, service := range services {
		if service.Location != samlConfig().ACSURL {
			t.Fatalf("unexpected callback location: %q", service.Location)
		}
		post = post || service.Binding == crewjamsaml.HTTPPostBinding
	}
	if !post {
		t.Fatal("SP metadata did not advertise a POST callback")
	}
}

func TestSAMLRejectsConsolePolicyDowngrades(t *testing.T) {
	no := false
	cases := map[string]func(*authsaml.Config){
		"HTTP callback":          func(c *authsaml.Config) { c.ACSURL = "http://console.example.com/acs" },
		"relative callback":      func(c *authsaml.Config) { c.ACSURL = "/acs" },
		"callback credentials":   func(c *authsaml.Config) { c.ACSURL = "https://user@console.example.com/acs" },
		"callback fragment":      func(c *authsaml.Config) { c.ACSURL += "#fragment" },
		"unsolicited response":   func(c *authsaml.Config) { c.AllowIDPInitiated = true },
		"implicit replay cache":  func(c *authsaml.Config) { c.ReplayCache = nil },
		"missing destination":    func(c *authsaml.Config) { c.RequireDestination = &no },
		"weak signature allowed": func(c *authsaml.Config) { c.RejectWeakSignatures = &no },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			config := samlConfig()
			change(&config)
			if _, err := NewSAMLProvider(config); err == nil {
				t.Fatal("unsafe console SAML configuration was accepted")
			}
		})
	}
}
