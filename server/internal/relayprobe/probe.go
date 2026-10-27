// Package relayprobe checks the pinned relay's rejection path without credentials.
package relayprobe

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"time"

	"github.com/fatedier/yamux"
)

var ErrProbe = errors.New("relay rejection path could not be verified")
var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$`)

const ProtocolVersion = "0.71.1"

// Check uses the frp 0.71.1 legacy Login framing over its pinned Yamux transport.
// Login plugins run before control admission. This message has an invalid claim
// and no token, device secret, signed identity, run ID or requested proxy.
func Check(ctx context.Context, address, serverName string, ca []byte) (string, error) {
	peer, err := netip.ParseAddrPort(address)
	if err != nil || !peer.Addr().IsLoopback() || peer.Port() == 0 || serverName == "" || len(serverName) > 253 || len(ca) == 0 || len(ca) > 65536 {
		return "", ErrProbe
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return "", ErrProbe
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second}, Config: &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12}}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return "", ErrProbe
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if connection.SetDeadline(deadline) != nil {
		return "", ErrProbe
	}
	config := yamux.DefaultConfig()
	config.AcceptBacklog = 1
	config.EnableKeepAlive = false
	config.ConnectionWriteTimeout = time.Second
	config.StreamOpenTimeout = time.Second
	config.StreamCloseTimeout = time.Second
	config.LogOutput = io.Discard
	session, err := yamux.Client(connection, config)
	if err != nil {
		return "", ErrProbe
	}
	defer session.Close()
	stream, err := session.OpenStream()
	if err != nil {
		return "", ErrProbe
	}
	defer stream.Close()
	if stream.SetDeadline(deadline) != nil {
		return "", ErrProbe
	}
	var identity [16]byte
	if _, err := rand.Read(identity[:]); err != nil {
		return "", ErrProbe
	}
	identity[6] = (identity[6] & 15) | 64
	identity[8] = (identity[8] & 63) | 128
	id := fmt.Sprintf("%x-%x-%x-%x-%x", identity[:4], identity[4:6], identity[6:8], identity[8:10], identity[10:])
	body, err := json.Marshal(struct {
		Version string            `json:"version"`
		Metas   map[string]string `json:"metas"`
	}{Version: ProtocolVersion, Metas: map[string]string{"device_id": id, "domain_claim": "doctor-invalid-claim"}})
	if err != nil {
		return "", ErrProbe
	}
	header := make([]byte, 9)
	header[0] = 'o'
	binary.BigEndian.PutUint64(header[1:], uint64(len(body)))
	if _, err := io.Copy(stream, bytes.NewReader(append(header, body...))); err != nil {
		return "", ErrProbe
	}
	if _, err := io.ReadFull(stream, header); err != nil || header[0] != '1' {
		return "", ErrProbe
	}
	length := binary.BigEndian.Uint64(header[1:])
	if length < 2 || length > 4096 {
		return "", ErrProbe
	}
	response := make([]byte, int(length))
	if _, err := io.ReadFull(stream, response); err != nil {
		return "", ErrProbe
	}
	return rejectionVersion(response)
}

func rejectionVersion(raw []byte) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return "", ErrProbe
	}
	fields := map[string]string{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return "", ErrProbe
		}
		if _, exists := fields[key]; exists {
			return "", ErrProbe
		}
		if key != "version" && key != "run_id" && key != "error" {
			return "", ErrProbe
		}
		var value *string
		if decoder.Decode(&value) != nil || value == nil {
			return "", ErrProbe
		}
		fields[key] = *value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return "", ErrProbe
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || !versionPattern.MatchString(fields["version"]) || fields["run_id"] != "" || fields["error"] != "not_authorized" {
		return "", ErrProbe
	}
	return fields["version"], nil
}
