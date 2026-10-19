package setup

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
)

// externalBase removes the bundled TLS owner before Compose reads either file.
// Fail closed if the reviewed service layout changes.
func externalBase(data []byte) ([]byte, error) {
	before, after, ok := bytes.Cut(data, []byte("\n  caddy:\n"))
	if !ok || bytes.Contains(after, []byte("\n  caddy:\n")) {
		return nil, errors.New("bundled proxy service boundary is invalid")
	}
	service, tail, ok := bytes.Cut(after, []byte("\nnetworks:\n"))
	if !ok {
		return nil, errors.New("bundled proxy network boundary is invalid")
	}
	if regexp.MustCompile(`(?m)^  [a-zA-Z][^\n]*:`).Match(service) {
		return nil, errors.New("unexpected service after bundled proxy")
	}
	return append(append(before, []byte("\nnetworks:\n")...), tail...), nil
}

func externalCaddy(config Config) []byte {
	w, d := config.originPorts()
	return []byte(fmt.Sprintf(`%s {
    @internal path /healthz /healthz/* /api/v1/frp /api/v1/frp/*
    respond @internal 404
    @device path /api/v1/devices/*
    reverse_proxy @device 127.0.0.1:%d {
        header_up Host %s
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto https
    }
    reverse_proxy 127.0.0.1:%d {
        header_up Host %s
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto https
    }
}
`, config.ConsoleHost, d, config.ConsoleHost, w, config.ConsoleHost))
}
