// Package traffic defines exact display values, never access policy.
package traffic

import (
	"errors"
	"math/big"
	"regexp"
	"time"
)

var decimal = regexp.MustCompile(`^(0|[1-9][0-9]{0,63})$`)

func ValidWarning(value string) bool {
	return value == "" || len(value) <= 30 && decimal.MatchString(value)
}

func ValidMonth(value string) bool {
	month, err := time.Parse("2006-01", value)
	return err == nil && len(value) == 7 && month.Year() > 0 && month.Format("2006-01") == value
}

// Consistent rejects rounded or malformed transport values before display.
func Consistent(in, out, total string) bool {
	if !decimal.MatchString(in) || !decimal.MatchString(out) || !decimal.MatchString(total) {
		return false
	}
	incoming, _ := new(big.Int).SetString(in, 10)
	outgoing, _ := new(big.Int).SetString(out, 10)
	return new(big.Int).Add(incoming, outgoing).String() == total
}

func Warning(total, threshold string) (*string, bool, error) {
	if !decimal.MatchString(total) || !ValidWarning(threshold) {
		return nil, false, errors.New("invalid traffic display value")
	}
	if threshold == "" || threshold == "0" {
		return nil, false, nil
	}
	value, _ := new(big.Int).SetString(total, 10)
	limit, _ := new(big.Int).SetString(threshold, 10)
	return &threshold, value.Cmp(limit) > 0, nil
}
