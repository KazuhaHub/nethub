package sso

import (
	"errors"
	"net/url"

	authsaml "github.com/KazuhaHub/authcore/saml"
	crewjamsaml "github.com/crewjam/saml"
)

// NewSAMLProvider applies console policy and delegates SAML to authcore.
// The caller supplies trusted metadata and a persistent replay store.
func NewSAMLProvider(config authsaml.Config) (*authsaml.Provider, error) {
	acs, err := url.Parse(config.ACSURL)
	if err != nil || acs.Scheme != "https" || acs.Hostname() == "" || acs.User != nil || acs.Fragment != "" {
		return nil, errors.New("SAML callback must be an absolute HTTPS URL")
	}
	if config.AllowIDPInitiated {
		return nil, errors.New("SAML login must originate from the console")
	}
	if config.ReplayCache == nil {
		return nil, errors.New("SAML requires an explicit replay store")
	}
	if config.RequireDestination != nil && !*config.RequireDestination {
		return nil, errors.New("SAML destination validation cannot be disabled")
	}
	if config.RejectWeakSignatures != nil && !*config.RejectWeakSignatures {
		return nil, errors.New("SAML weak-signature rejection cannot be disabled")
	}
	if config.NameIDFormat != "" && config.NameIDFormat != crewjamsaml.PersistentNameIDFormat {
		return nil, errors.New("SAML account identity requires a persistent NameID")
	}
	config.NameIDFormat = crewjamsaml.PersistentNameIDFormat
	config.StrictAttributes = true
	return authsaml.New(config)
}
