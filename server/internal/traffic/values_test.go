package traffic

import "testing"

func TestExactWarningsAndMonthBounds(t *testing.T) {
	for _, value := range []string{"", "0", "1000000000000", "999999999999999999999999999999"} {
		if !ValidWarning(value) {
			t.Fatal("valid warning rejected")
		}
	}
	for _, value := range []string{"01", "-1", "1.0", "1e3", " 1", "1000000000000000000000000000000"} {
		if ValidWarning(value) {
			t.Fatal("noncanonical warning accepted")
		}
	}
	for _, value := range []string{"0000-01", "2026-1", "2026-13", "2026-10-01"} {
		if ValidMonth(value) {
			t.Fatal("invalid month accepted")
		}
	}
	if !ValidMonth("0001-01") || !ValidMonth("9999-12") {
		t.Fatal("valid Gregorian month bounds refused")
	}
	if !Consistent("9223372036854775807", "9223372036854775807", "18446744073709551614") || Consistent("9223372036854775807", "9223372036854775807", "18446744073709552000") {
		t.Fatal("wide sum precision was lost")
	}
	for _, test := range []struct {
		total, limit string
		warning      bool
	}{{"9007199254740993", "9007199254740992", true}, {"9007199254740992", "9007199254740992", false}, {"999", "0", false}, {"999", "", false}} {
		_, warning, err := Warning(test.total, test.limit)
		if err != nil || warning != test.warning {
			t.Fatal("warning comparison lost integer precision")
		}
	}
}
