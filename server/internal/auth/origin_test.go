package auth

import (
	"net/http/httptest"
	"testing"
)

func TestOriginPolicy(t *testing.T) {
	policy, err := NewOriginPolicy("https://console.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, values := range [][]string{nil, {"https://console.example.com"}, {"https://evil.example.com"}, {"null"}, {"https://console.example.com.evil.example"}, {"https://console.example.com", "https://console.example.com"}, {"https://console.example.com/"}} {
		request := httptest.NewRequest("POST", "https://console.example.com/login", nil)
		for _, value := range values {
			request.Header.Add("Origin", value)
		}
		want := len(values) == 1 && values[0] == "https://console.example.com"
		if policy.Check(request, true) != want || policy.Check(request, false) != (want || len(values) == 0) {
			t.Fatalf("origin policy accepted an incorrect header shape: %v", values)
		}
	}
	for _, origin := range []string{"", "http://console.example.com", "https://user@console.example.com", "https://console.example.com/", "https://console.example.com?", "https://console.example.com#fragment"} {
		if _, err := NewOriginPolicy(origin); err == nil {
			t.Fatalf("accepted invalid origin %q", origin)
		}
	}
}
