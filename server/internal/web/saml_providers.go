package web

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

func (s *Server) samlMetadata(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix+"/saml/"), "/")
	if len(parts) != 2 || !providerSlug.MatchString(parts[0]) || parts[1] != "metadata" {
		writeError(w, r, 404, "not_found", "Not found")
		return
	}
	if !allowMethod(w, r, "GET") {
		return
	}
	if r.URL.RawQuery != "" {
		s.providerError(w, r, ErrProviderInput)
		return
	}
	p := s.samlLocations(SAMLProvider{Slug: parts[0]})
	document, err := s.repository.SAMLMetadata(r.Context(), parts[0], p.MetadataURI, p.ACSURI)
	if err != nil {
		s.providerError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml; charset=utf-8")
	w.WriteHeader(200)
	if r.Method != "HEAD" {
		w.Write(document)
	}
}

func (s *Server) samlLocations(p SAMLProvider) SAMLProvider {
	p.MetadataURI = "https://" + s.host + prefix + "/saml/" + p.Slug + "/metadata"
	p.ACSURI = "https://" + s.host + prefix + "/saml/" + p.Slug + "/callback"
	return p
}

func (s *Server) samlProviders(w http.ResponseWriter, r *http.Request) {
	session, ok := s.adminSession(w, r, false)
	if !ok {
		return
	}
	values, err := netURLQuery(r)
	if err != nil {
		s.providerError(w, r, ErrProviderInput)
		return
	}
	query := UserQuery{Limit: 50}
	for key, list := range values {
		if len(list) != 1 {
			s.providerError(w, r, ErrProviderInput)
			return
		}
		switch key {
		case "limit":
			query.Limit, err = strconv.Atoi(list[0])
			if err != nil || query.Limit < 1 || query.Limit > 200 {
				s.providerError(w, r, ErrProviderInput)
				return
			}
		case "cursor":
			value, e := base64.RawURLEncoding.Strict().DecodeString(list[0])
			if e != nil || len(list[0]) > 64 || !uuidPattern.Match(value) {
				s.providerError(w, r, ErrProviderInput)
				return
			}
			query.AfterID = string(value)
		default:
			s.providerError(w, r, ErrProviderInput)
			return
		}
	}
	page, err := s.repository.SAMLProviders(r.Context(), session.User.ID, query)
	if err != nil {
		s.providerError(w, r, err)
		return
	}
	for i, p := range page.Items {
		page.Items[i] = s.samlLocations(p)
	}
	writeJSON(w, r, 200, page)
}

func readSAMLPatch(w http.ResponseWriter, r *http.Request, create bool) (string, SAMLProviderPatch, bool) {
	fields := []string{"display_name", "entity_id", "metadata_xml", "email_attribute", "enabled"}
	if create {
		fields = append(fields, "slug")
	}
	var raw map[string]json.RawMessage
	// JSON escaping can expand a one-MiB XML document by up to six times. This
	// limit applies only after administrator/CSRF checks, not to other APIs.
	if !readJSONWithLimit(w, r, &raw, 6*(1<<20)+maxBody, fields...) {
		return "", SAMLProviderPatch{}, false
	}
	var slug string
	var patch SAMLProviderPatch
	for key, value := range raw {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			writeError(w, r, 400, "invalid_request", "Provider fields cannot be null")
			return "", SAMLProviderPatch{}, false
		}
		var target any
		switch key {
		case "slug":
			target = &slug
		case "display_name":
			patch.DisplayName = new(string)
			target = patch.DisplayName
		case "entity_id":
			patch.EntityID = new(string)
			target = patch.EntityID
		case "metadata_xml":
			patch.MetadataXML = new(string)
			target = patch.MetadataXML
		case "email_attribute":
			patch.EmailAttribute = new(string)
			target = patch.EmailAttribute
		case "enabled":
			patch.Enabled = new(bool)
			target = patch.Enabled
		}
		if json.Unmarshal(value, target) != nil {
			writeError(w, r, 400, "invalid_request", "Invalid provider field")
			return "", SAMLProviderPatch{}, false
		}
	}
	if len(raw) == 0 || create && (patch.DisplayName == nil || patch.EntityID == nil || patch.MetadataXML == nil || patch.EmailAttribute == nil || slug == "") {
		writeError(w, r, 400, "invalid_request", "Required provider fields are missing")
		return "", SAMLProviderPatch{}, false
	}
	return slug, patch, true
}

func (s *Server) createSAMLProvider(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	session, ok := s.adminSession(w, r, true)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		s.providerError(w, r, ErrProviderInput)
		return
	}
	slug, patch, ok := readSAMLPatch(w, r, true)
	if !ok {
		return
	}
	input := SAMLProviderInput{Slug: slug, DisplayName: *patch.DisplayName, EntityID: *patch.EntityID, MetadataXML: *patch.MetadataXML, EmailAttribute: *patch.EmailAttribute}
	if patch.Enabled != nil {
		input.Enabled = *patch.Enabled
	}
	input, err := NormalizeSAMLInput(input)
	if err != nil {
		s.providerError(w, r, err)
		return
	}
	p, err := s.repository.CreateSAMLProvider(r.Context(), session.User.ID, input, ip.Unmap())
	if err != nil {
		s.providerError(w, r, err)
		return
	}
	writeJSON(w, r, 201, s.samlLocations(p))
}

func (s *Server) mutateSAMLProvider(w http.ResponseWriter, r *http.Request, ip netip.Addr) {
	session, ok := s.adminSession(w, r, true)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, prefix+"/saml-providers/")
	if !uuidPattern.MatchString(id) || r.URL.RawQuery != "" {
		s.providerError(w, r, ErrProviderInput)
		return
	}
	if r.Method == "DELETE" {
		if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
			s.providerError(w, r, ErrProviderInput)
			return
		}
		if err := s.repository.DeleteSAMLProvider(r.Context(), session.User.ID, id, ip.Unmap()); err != nil {
			s.providerError(w, r, err)
			return
		}
		w.WriteHeader(204)
		return
	}
	_, patch, ok := readSAMLPatch(w, r, false)
	if !ok {
		return
	}
	p, err := s.repository.UpdateSAMLProvider(r.Context(), session.User.ID, id, patch, ip.Unmap())
	if err != nil {
		s.providerError(w, r, err)
		return
	}
	writeJSON(w, r, 200, s.samlLocations(p))
}
