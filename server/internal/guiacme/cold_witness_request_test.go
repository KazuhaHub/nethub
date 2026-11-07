package guiacme

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"testing"

	"github.com/KazuhaHub/nethub/server/internal/boundedjson"
)

type coldWitnessRequest struct {
	Version     int    `json:"version"`
	Host        string `json:"host"`
	ForwardPort int    `json:"forward_port"`
}

func decodeColdWitnessRequest(raw []byte) (coldWitnessRequest, error) {
	var request coldWitnessRequest
	refused := errors.New("cold witness request refused")
	if len(raw) > 4096 {
		return request, refused
	}
	fields, err := boundedjson.ObjectWithLimits(bytes.NewReader(raw), 4096, 8)
	if err != nil || len(fields) != 3 {
		return request, refused
	}
	for _, name := range []string{"version", "host", "forward_port"} {
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return request, refused
		}
	}
	if json.Unmarshal(raw, &request) != nil || request.Version != 1 ||
		!regexp.MustCompile(`^[a-z0-9]{8}\.devices\.example\.test$`).MatchString(request.Host) ||
		request.ForwardPort < 1024 || request.ForwardPort > 65535 {
		return request, refused
	}
	return request, nil
}

func TestColdHostWitnessRequestAdmission(t *testing.T) {
	valid := `{"version":1,"host":"abcdefgh.devices.example.test","forward_port":18441}`
	if request, err := decodeColdWitnessRequest([]byte(valid)); err != nil || request.ForwardPort != 18441 {
		t.Fatal("valid isolated witness request refused")
	}
	for _, input := range []string{
		`[]`, `{}`, valid + `{}`, valid + `null`,
		`{"version":1,"version":1,"host":"abcdefgh.devices.example.test","forward_port":18441}`,
		`{"version":1,"host":null,"forward_port":18441}`,
		`{"version":1,"host":"abcdefgh.devices.example.test","forward_port":18441,"extra":true}`,
		`{"version":2,"host":"abcdefgh.devices.example.test","forward_port":18441}`,
		`{"version":1,"host":"abcdefgh.other.example.test","forward_port":18441}`,
		`{"version":1,"host":"abcdefgh.devices.example.test\n","forward_port":18441}`,
		`{"version":1,"host":"abcdefgh.devices.example.test","forward_port":80}`,
		`{"version":1,"host":"abcdefgh.devices.example.test","forward_port":65536}`,
		`{"version":1,"host":"abcdefgh.devices.example.test","forward_port":18441.5}`,
	} {
		if _, err := decodeColdWitnessRequest([]byte(input)); err == nil {
			t.Fatal("malformed, duplicate, foreign or unbounded witness request accepted")
		}
	}
}
