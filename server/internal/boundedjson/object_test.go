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
