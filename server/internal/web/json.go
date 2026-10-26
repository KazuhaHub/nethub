package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"
)

const maxBody = 64 * 1024

func writeJSON(w http.ResponseWriter, r *http.Request, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if r.Method != "HEAD" {
		json.NewEncoder(w).Encode(value)
	}
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSON(w, r, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func readJSON(w http.ResponseWriter, r *http.Request, value any, fields ...string) bool {
	return readJSONWithLimit(w, r, value, maxBody, fields...)
}

func readJSONWithLimit(w http.ResponseWriter, r *http.Request, value any, limit int64, fields ...string) bool {
	media, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(r.Header.Values("Content-Type")) != 1 || parameters["charset"] != "" && !strings.EqualFold(parameters["charset"], "utf-8") || r.Header.Get("Content-Encoding") != "" {
		writeError(w, r, 415, "unsupported_media_type", "Use application/json with UTF-8 encoding")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	data, err := io.ReadAll(r.Body)
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, r, 413, "payload_too_large", fmt.Sprintf("Request body exceeds %d KiB", limit/1024))
		return false
	}
	if err != nil || !utf8.Valid(data) {
		writeError(w, r, 400, "invalid_request", "Invalid JSON body")
		return false
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		writeError(w, r, 400, "invalid_request", "Request body must be a JSON object")
		return false
	}
	// Reject repeated top-level keys before decoding the documented schema.
	keys := json.NewDecoder(bytes.NewReader(data))
	keys.Token()
	seen := map[string]bool{}
	allowed := map[string]bool{}
	for _, field := range fields {
		allowed[field] = true
	}
	for keys.More() {
		key, err := keys.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] || !allowed[name] {
			writeError(w, r, 400, "invalid_request", "Invalid, unknown, or repeated JSON field")
			return false
		}
		seen[name] = true
		var field json.RawMessage
		if err := keys.Decode(&field); err != nil {
			writeError(w, r, 400, "invalid_request", "Invalid JSON body")
			return false
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		writeError(w, r, 400, "invalid_request", "Invalid or unknown JSON field")
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		writeError(w, r, 400, "invalid_request", "Expected exactly one JSON object")
		return false
	}
	return true
}
