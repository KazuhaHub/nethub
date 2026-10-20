package protocol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/guicert"
)

var ErrCertificateDeliveryVersion = errors.New("certificate delivery requires protocol 1.3 or later within major 1")

const CertificateTimeLayout = "2006-01-02T15:04:05.000000Z"

type CertificateIssuedRequest struct {
	Identity
	RequestID      string `json:"request_id"`
	CSRFingerprint string `json:"csr_fingerprint"`
}

type CertificateGeneration struct {
	ID              string `json:"generation_id"`
	Generation      int    `json:"generation"`
	ChainPEM        string `json:"chain_pem"`
	LeafFingerprint string `json:"leaf_fingerprint"`
	NotBefore       string `json:"not_before"`
	NotAfter        string `json:"not_after"`
	ValidUntil      string `json:"valid_until"`
	RenewAfter      string `json:"renew_after"`
}

type CertificateDelivery struct {
	CertificateSettings
	Issued *CertificateGeneration `json:"issued"`
}

func ValidateCertificateDeliveryIdentity(identity Identity) error {
	if err := ValidateCertificateIdentity(identity); err != nil {
		return err
	}
	if strings.SplitN(identity.AgentProtocolVersion, ".", 3)[1] == "2" {
		return ErrCertificateDeliveryVersion
	}
	return nil
}

func (r CertificateIssuedRequest) Validate() error {
	if err := ValidateCertificateDeliveryIdentity(r.Identity); err != nil {
		return err
	}
	if !deviceIDPattern.MatchString(r.RequestID) || !fingerprintPattern.MatchString(r.CSRFingerprint) {
		return ErrInvalidRequest
	}
	return nil
}

func DecodeCertificateIssued(reader io.Reader) (CertificateIssuedRequest, error) {
	var result CertificateIssuedRequest
	data, err := selectedLifecycle(reader, []string{"agent_protocol_version", "device_id", "request_id", "csr_fingerprint"}, nil)
	if err != nil || json.Unmarshal(data, &result) != nil {
		return result, ErrInvalidRequest
	}
	return result, result.Validate()
}

// Validate checks public correlation and integrity, not a trusted root or
// successful application. The device must independently verify its own trust.
func (r CertificateDelivery) Validate() error {
	return r.ValidateAt(time.Now())
}

func (r CertificateDelivery) ValidateAt(now time.Time) error {
	if now.IsZero() || ValidateCertificateDeliveryIdentity(r.Identity) != nil || r.CertificateSettings.Validate() != nil || r.Request == nil {
		return ErrInvalidRequest
	}
	if r.Issued == nil {
		return nil
	}
	v := r.Issued
	if !deviceIDPattern.MatchString(v.ID) || v.Generation < 1 || v.Generation > 2147483647 || !fingerprintPattern.MatchString(v.LeafFingerprint) || len(v.ChainPEM) == 0 || len(v.ChainPEM) > 32768 {
		return ErrInvalidRequest
	}
	der, err := CertificateDER(r.Request.CSRDER)
	if err != nil {
		return err
	}
	chain, err := guicert.InspectChain([]byte(v.ChainPEM), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), r.AssignedHost, now)
	if err != nil || hex.EncodeToString(chain.Fingerprint[:]) != v.LeafFingerprint || !bytes.Equal(chain.PEM, []byte(v.ChainPEM)) {
		return ErrInvalidRequest
	}
	stamps := make([]time.Time, 4)
	for i, value := range []string{v.NotBefore, v.NotAfter, v.ValidUntil, v.RenewAfter} {
		stamp, err := time.Parse(CertificateTimeLayout, value)
		if err != nil || stamp.Format(CertificateTimeLayout) != value {
			return ErrInvalidRequest
		}
		stamps[i] = stamp
	}
	if !stamps[0].Equal(chain.NotBefore) || !stamps[1].Equal(chain.NotAfter) || stamps[2].After(chain.ValidUntil) || !stamps[2].After(now) || !stamps[3].Before(stamps[2]) || !stamps[3].After(stamps[0]) {
		return ErrInvalidRequest
	}
	return nil
}
