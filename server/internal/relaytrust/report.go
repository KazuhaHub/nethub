package relaytrust

import (
	"errors"
	"regexp"
)

var ErrChanged = errors.New("relay trust generation changed; fetch current trust")
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Report struct {
	GenerationID string
	Number       int
	Fingerprint  string
}

func (r Report) Valid() bool {
	return validID(r.GenerationID) && r.Number >= 1 && r.Number <= 2147483647 && digestPattern.MatchString(r.Fingerprint)
}
