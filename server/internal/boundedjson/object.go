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
	return ObjectWithLimits(reader, MaxBytes, 256)
}

// ObjectWithLimits permits bounded larger server responses without relaxing
// the default device request limits.
func ObjectWithLimits(reader io.Reader, maxBytes, maxItems int) (map[string]json.RawMessage, error) {
	if maxBytes < 1 || maxBytes > 4*1024*1024 || maxItems < 1 || maxItems > 4096 {
		return nil, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(reader, int64(maxBytes)+1))
	if err != nil || len(data) > maxBytes || !utf8.Valid(data) || !json.Valid(data) {
		return nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := check(decoder, 0, maxItems); err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil || object == nil {
		return nil, ErrInvalid
	}
	return object, nil
}

func check(decoder *json.Decoder, depth, maxItems int) error {
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
			if err := check(decoder, depth+1, maxItems); err != nil {
				return err
			}
		}
	case '[':
		for count := 0; decoder.More(); count++ {
			if count >= maxItems {
				return ErrInvalid
			}
			if err := check(decoder, depth+1, maxItems); err != nil {
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
