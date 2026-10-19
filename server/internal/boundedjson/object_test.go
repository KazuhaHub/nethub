package boundedjson

import (
	"fmt"
	"strings"
	"testing"
)

func TestObjectRejectsAmbiguousOrUnboundedDocuments(t *testing.T) {
	var fields, elements []string
	for i := 0; i < 65; i++ {
		fields = append(fields, fmt.Sprintf(`"field%d":true`, i))
	}
	for range 257 {
		elements = append(elements, "0")
	}
	for _, data := range []string{"null", "[]", `{} {}`, `{"a":1,"\u0061":2}`,
		`{"extension":{"x":1,"x":2}}`, "{\"x\":\"\xff\"}", strings.Repeat(" ", MaxBytes+1),
		`{"x":` + strings.Repeat("[", 17) + "0" + strings.Repeat("]", 17) + "}",
		"{" + strings.Join(fields, ",") + "}", `{"x":[` + strings.Join(elements, ",") + "]}"} {
		if _, err := Object(strings.NewReader(data)); err == nil {
			t.Fatal("accepted an ambiguous or unbounded document")
		}
	}
	if _, err := Object(strings.NewReader("{" + strings.Join(fields[:64], ",") + "}")); err != nil {
		t.Fatal("rejected exactly 64 fields")
	}
	if _, err := Object(strings.NewReader(`{"x":[` + strings.Join(elements[:256], ",") + "]}")); err != nil {
		t.Fatal("rejected exactly 256 elements")
	}
}

func TestExplicitResponseLimitsPreserveDefaultRequestBounds(t *testing.T) {
	var items []string
	for range 1025 {
		items = append(items, "0")
	}
	data := `{"items":[` + strings.Join(items[:1024], ",") + `],"unknown_number":1e309}`
	if _, err := ObjectWithLimits(strings.NewReader(data), 1024*1024, 1024); err != nil {
		t.Fatal("valid larger response or unknown numeric extension rejected")
	}
	if _, err := Object(strings.NewReader(data)); err == nil {
		t.Fatal("larger response weakened the default request array limit")
	}
	if _, err := ObjectWithLimits(strings.NewReader(`{"items":[`+strings.Join(items, ",")+`]}`), 1024*1024, 1024); err == nil {
		t.Fatal("explicit array budget was not enforced")
	}
	for _, limit := range []struct{ bytes, items int }{{0, 1}, {1, 0}, {4*1024*1024 + 1, 1}, {1, 4097}} {
		if _, err := ObjectWithLimits(strings.NewReader(`{}`), limit.bytes, limit.items); err == nil {
			t.Fatal("invalid explicit parser limits accepted")
		}
	}
}
