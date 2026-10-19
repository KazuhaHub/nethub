// Package boundedjson reads small JSON objects without ambiguous duplicate keys.
package boundedjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

const MaxBytes = 65536

var ErrInvalid = errors.New("invalid bounded JSON object")

// Object bounds the document, nesting, object fields and array elements.
func Object(reader io.Reader) (map[string]json.RawMessage, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxBytes+1))
	if err != nil || len(data) > MaxBytes || !utf8.Valid(data) || !json.Valid(data) {
		return nil, ErrInvalid
	}
	if err := check(json.NewDecoder(bytes.NewReader(data)), 0); err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil || object == nil {
		return nil, ErrInvalid
	}
	return object, nil
}

func check(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalid
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] || len(seen) >= 64 {
				return ErrInvalid
			}
			seen[name] = true
			if err := check(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for count := 0; decoder.More(); count++ {
			if count >= 256 {
				return ErrInvalid
			}
			if err := check(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return ErrInvalid
	}
	if _, err := decoder.Token(); err != nil {
		return ErrInvalid
	}
	return nil
}
