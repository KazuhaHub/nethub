package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/guicert"
)

var ErrCertificateVersion = errors.New("certificate requests require protocol 1.2 or later within major 1")
var guiAssignedHost = regexp.MustCompile(`^[a-z0-9]{8}(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
var fingerprintPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type CertificateSubmit struct {
	Identity
	CSRDER string `json:"csr_der"`
}

type CertificateRecord struct {
	RequestID      string `json:"request_id"`
	CSRDER         string `json:"csr_der"`
	CSRFingerprint string `json:"csr_fingerprint"`
	CreatedAt      string `json:"created_at"`
}

type CertificateSettings struct {
	Identity
	AssignedHost      string             `json:"assigned_host"`
	GUIKeyFingerprint string             `json:"gui_key_fingerprint"`
	Request           *CertificateRecord `json:"request"`
}

func ValidateCertificateIdentity(identity Identity) error {
	if err := identity.Validate(); err != nil {
		return err
	}
	minor := strings.SplitN(identity.AgentProtocolVersion, ".", 3)[1]
	if minor == "0" || minor == "1" {
		return ErrCertificateVersion
	}
	return nil
}

func DecodeCertificateSettings(reader io.Reader) (Identity, error) {
	identity, err := DecodeIdentity(reader)
	if err != nil {
		return Identity{}, err
	}
	return identity, ValidateCertificateIdentity(identity)
}

func DecodeCertificateSubmit(reader io.Reader) (CertificateSubmit, error) {
	var result CertificateSubmit
	data, err := selectedLifecycle(reader, []string{"agent_protocol_version", "device_id", "csr_der"}, nil)
	if err != nil || json.Unmarshal(data, &result) != nil {
		return result, ErrInvalidRequest
	}
	if err := result.Validate(); err != nil {
		return CertificateSubmit{}, err
	}
	return result, nil
}

func CertificateDER(value string) ([]byte, error) {
	if len(value) == 0 || len(value) > 5464 {
		return nil, ErrInvalidRequest
	}
	der, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(der) == 0 || len(der) > 4096 || base64.StdEncoding.EncodeToString(der) != value {
		return nil, ErrInvalidRequest
	}
	return der, nil
}

func (r CertificateSubmit) Validate() error {
	if err := ValidateCertificateIdentity(r.Identity); err != nil {
		return err
	}
	_, err := CertificateDER(r.CSRDER)
	return err
}

// Validate checks the actual public response, including CSR/name/key correlation.
// It is not a replacement for assignment authorization in the database store.
func (r CertificateSettings) Validate() error {
	if err := ValidateCertificateIdentity(r.Identity); err != nil {
		return err
	}
	if len(r.AssignedHost) > 253 || !guiAssignedHost.MatchString(r.AssignedHost) || !fingerprintPattern.MatchString(r.GUIKeyFingerprint) {
		return ErrInvalidRequest
	}
	if r.Request == nil {
		return nil
	}
	record := r.Request
	if !deviceIDPattern.MatchString(record.RequestID) || !fingerprintPattern.MatchString(record.CSRFingerprint) {
		return ErrInvalidRequest
	}
	stamp, err := time.Parse("2006-01-02T15:04:05.000000Z", record.CreatedAt)
	if err != nil || stamp.Format("2006-01-02T15:04:05.000000Z") != record.CreatedAt {
		return ErrInvalidRequest
	}
	der, err := CertificateDER(record.CSRDER)
	if err != nil {
		return err
	}
	csr, err := guicert.ValidateCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), r.AssignedHost)
	key := sha256.Sum256(csr.PublicKey)
	if err != nil || hex.EncodeToString(csr.Fingerprint[:]) != record.CSRFingerprint || hex.EncodeToString(key[:]) != r.GUIKeyFingerprint {
		return ErrInvalidRequest
	}
	return nil
}
