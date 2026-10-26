package sso

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"

	crewjamsaml "github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
)

const samlMetadataNamespace = "urn:oasis:names:tc:SAML:2.0:metadata"

var ErrSAMLMetadata = errors.New("invalid SAML identity-provider metadata")

// ParseSAMLMetadata selects an explicitly named IdP from administrator-supplied
// metadata. It performs no network requests or metadata signature verification:
// the administrator must obtain the document through a trusted channel. Runtime
// admission must still enforce the returned validity deadline and DNS policy.
func ParseSAMLMetadata(document []byte, entityID string) (*crewjamsaml.EntityDescriptor, error) {
	if len(document) == 0 || len(document) > 1<<20 || entityID == "" || len(entityID) > 4096 || strings.TrimSpace(entityID) != entityID {
		return nil, ErrSAMLMetadata
	}
	root, err := inspectSAMLMetadata(document)
	if err != nil || xrv.Validate(bytes.NewReader(document)) != nil {
		return nil, ErrSAMLMetadata
	}
	var selected *crewjamsaml.EntityDescriptor
	selectEntity := func(entity crewjamsaml.EntityDescriptor, inherited time.Time) error {
		if entity.EntityID != entityID {
			return nil
		}
		if selected != nil {
			return ErrSAMLMetadata
		}
		entity.ValidUntil = earlierSAMLDeadline(entity.ValidUntil, inherited)
		selected = &entity
		return nil
	}
	if root.Local == "EntityDescriptor" {
		var entity crewjamsaml.EntityDescriptor
		if xml.Unmarshal(document, &entity) != nil || selectEntity(entity, time.Time{}) != nil {
			return nil, ErrSAMLMetadata
		}
	} else {
		var group crewjamsaml.EntitiesDescriptor
		if xml.Unmarshal(document, &group) != nil {
			return nil, ErrSAMLMetadata
		}
		var walk func(crewjamsaml.EntitiesDescriptor, time.Time) error
		walk = func(group crewjamsaml.EntitiesDescriptor, inherited time.Time) error {
			if group.ValidUntil != nil {
				inherited = earlierSAMLDeadline(inherited, *group.ValidUntil)
			}
			for _, entity := range group.EntityDescriptors {
				if err := selectEntity(entity, inherited); err != nil {
					return err
				}
			}
			for _, child := range group.EntitiesDescriptors {
				if err := walk(child, inherited); err != nil {
					return err
				}
			}
			return nil
		}
		if walk(group, time.Time{}) != nil {
			return nil, ErrSAMLMetadata
		}
	}
	if selected == nil || len(selected.IDPSSODescriptors) != 1 {
		return nil, ErrSAMLMetadata
	}
	role := selected.IDPSSODescriptors[0]
	if !containsSAMLProtocol(role.ProtocolSupportEnumeration) {
		return nil, ErrSAMLMetadata
	}
	if role.ValidUntil != nil {
		selected.ValidUntil = earlierSAMLDeadline(selected.ValidUntil, *role.ValidUntil)
	}
	redirects, certificates := 0, 0
	for _, endpoint := range role.SingleSignOnServices {
		if endpoint.Binding != crewjamsaml.HTTPRedirectBinding {
			continue
		}
		location, err := url.Parse(endpoint.Location)
		if err != nil {
			return nil, ErrSAMLMetadata
		}
		if _, err := outboundURL(location); err != nil {
			return nil, ErrSAMLMetadata
		}
		query, err := url.ParseQuery(location.RawQuery)
		if err != nil {
			return nil, ErrSAMLMetadata
		}
		for _, reserved := range []string{"SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature"} {
			if _, exists := query[reserved]; exists {
				return nil, ErrSAMLMetadata
			}
		}
		redirects++
	}
	for _, key := range role.KeyDescriptors {
		if key.Use != "" && key.Use != "signing" {
			continue
		}
		for _, value := range key.KeyInfo.X509Data.X509Certificates {
			der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(value.Data), ""))
			if err != nil {
				return nil, ErrSAMLMetadata
			}
			certificate, err := x509.ParseCertificate(der)
			if err != nil || !strongSAMLMetadataKey(certificate) {
				return nil, ErrSAMLMetadata
			}
			certificates++
		}
	}
	if redirects == 0 || certificates == 0 {
		return nil, ErrSAMLMetadata
	}
	return selected, nil
}

func containsSAMLProtocol(value string) bool {
	for _, protocol := range strings.Fields(value) {
		if protocol == "urn:oasis:names:tc:SAML:2.0:protocol" {
			return true
		}
	}
	return false
}

func earlierSAMLDeadline(a, b time.Time) time.Time {
	if a.IsZero() || !b.IsZero() && b.Before(a) {
		return b
	}
	return a
}

func strongSAMLMetadataKey(certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}
	switch key := certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen() >= 2048
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize >= 256
	default:
		return false
	}
}

func inspectSAMLMetadata(document []byte) (xml.Name, error) {
	decoder := xml.NewDecoder(bytes.NewReader(document))
	var root xml.Name
	depth, roots, entities := 0, 0, 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			if depth == 0 && roots == 1 {
				return root, nil
			}
			return root, ErrSAMLMetadata
		}
		if err != nil {
			return root, ErrSAMLMetadata
		}
		switch token := token.(type) {
		case xml.StartElement:
			attributes := make(map[xml.Name]struct{}, len(token.Attr))
			for _, attribute := range token.Attr {
				if _, duplicate := attributes[attribute.Name]; duplicate {
					return root, ErrSAMLMetadata
				}
				attributes[attribute.Name] = struct{}{}
			}
			if depth == 0 {
				roots++
				root = token.Name
				if roots != 1 || root.Space != samlMetadataNamespace || root.Local != "EntityDescriptor" && root.Local != "EntitiesDescriptor" {
					return root, ErrSAMLMetadata
				}
			}
			depth++
			if depth > 64 {
				return root, ErrSAMLMetadata
			}
			switch token.Name.Local {
			case "EntityDescriptor", "EntitiesDescriptor", "IDPSSODescriptor", "KeyDescriptor", "SingleSignOnService":
				if token.Name.Space != samlMetadataNamespace {
					return root, ErrSAMLMetadata
				}
			case "KeyInfo", "X509Data", "X509Certificate":
				if token.Name.Space != "http://www.w3.org/2000/09/xmldsig#" {
					return root, ErrSAMLMetadata
				}
			}
			if token.Name.Local == "EntityDescriptor" {
				entities++
				if entities > 128 {
					return root, ErrSAMLMetadata
				}
			}
		case xml.EndElement:
			depth--
		case xml.Directive:
			return root, ErrSAMLMetadata
		case xml.ProcInst:
			if token.Target != "xml" || roots != 0 {
				return root, ErrSAMLMetadata
			}
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(token)) != "" {
				return root, ErrSAMLMetadata
			}
		}
	}
}
