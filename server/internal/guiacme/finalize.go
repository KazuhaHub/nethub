package guiacme

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/guicert"
	"golang.org/x/crypto/acme"
)

var ErrNotReady = errors.New("ACME order is not ready")

// Issued is validated public material for an authenticated device delivery job.
// It proves neither current assignment authorization nor native installation.
type Issued struct {
	Order Order         `json:"-"`
	Chain guicert.Chain `json:"-"`
}

// FinalizeOrder requires a durable saved order and finalizing intent with this
// exact CSR. The worker must reauthorize the live assignment before this call and
// before persisting/delivering its result. Roots come from independent operator
// trust configuration, never from the downloaded chain or another CA response.
// A valid existing order is fetched without submitting its CSR again.
func (s *AccountStore) FinalizeOrder(ctx context.Context, saved Order, csr []byte, boundKey string, roots *x509.CertPool) (Issued, error) {
	if roots == nil {
		return Issued{}, ErrOrder
	}
	roots = roots.Clone()
	session, err := s.knownOrder(ctx, saved, csr, boundKey)
	if err != nil {
		return Issued{}, err
	}
	defer session.close()
	order, raw, err := session.savedOrder(saved)
	if err != nil {
		return Issued{}, err
	}
	if order.Status == acme.StatusPending || order.Status == acme.StatusProcessing {
		return Issued{}, ErrNotReady
	}
	if order.Status != acme.StatusReady && order.Status != acme.StatusValid {
		return Issued{}, ErrOrder
	}
	// Keep the exact bounded PEM response. The SDK's certificate parser can ignore
	// trailing data or headers; validating a re-encoded DER slice would lose those
	// wire-profile checks. No capture escapes this operation or enters a log.
	capture := &certificateCapture{base: session.client.transport, responses: map[string]capturedResponse{}}
	session.sdk.HTTPClient.Transport = capture
	certificateURL := order.CertificateURL
	if order.Status == acme.StatusReady {
		_, certificateURL, err = session.sdk.CreateCertFromOrder(session.ctx, raw, session.request.DER, true)
	} else {
		_, err = session.sdk.FetchCert(session.ctx, certificateURL, true)
	}
	if err != nil {
		return Issued{}, remoteError(session.ctx)
	}
	if session.ctx.Err() != nil {
		return Issued{}, ErrCancelled
	}
	// Recheck the same order after submission/download; an untrusted intermediate
	// finalize response does not establish the issued identity or certificate URL.
	current, _, err := session.savedOrder(saved)
	if err != nil {
		return Issued{}, err
	}
	if current.Status != acme.StatusValid || current.CertificateURL != certificateURL {
		return Issued{}, ErrOrder
	}
	response, ok := capture.responses[certificateURL]
	typeName, _, typeError := mime.ParseMediaType(response.contentType)
	if !ok || response.status != http.StatusOK || typeError != nil || typeName != "application/pem-certificate-chain" {
		return Issued{}, ErrOrder
	}
	chain, err := guicert.ValidateChain(response.body, csr, saved.Host, roots, time.Now())
	if err != nil {
		return Issued{}, ErrOrder
	}
	return Issued{Order: current, Chain: chain}, nil
}

type capturedResponse struct {
	body        []byte
	status      int
	contentType string
}

type certificateCapture struct {
	base      *transport
	responses map[string]capturedResponse
	count     int
}

func (capture *certificateCapture) RoundTrip(request *http.Request) (*http.Response, error) {
	capture.count++
	if capture.count > 32 {
		return nil, ErrRemote
	}
	response, err := capture.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	response.Body.Close()
	if err != nil || len(body) > maxResponse {
		return nil, ErrRemote
	}
	capture.responses[request.URL.String()] = capturedResponse{body: bytes.Clone(body), status: response.StatusCode, contentType: response.Header.Get("Content-Type")}
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}
