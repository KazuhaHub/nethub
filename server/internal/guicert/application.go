package guicert

// ApplicationReport is authenticated device reporting, not independent proof
// of a live GUI or authority to issue another certificate.
type ApplicationReport struct {
	DeviceID           string
	RequestID          string
	RequestFingerprint string
	GenerationID       string
	Generation         int
	Fingerprint        string
}
