package dnsquery

import "testing"

func TestNormalizeResolver(t *testing.T) {
	cases := map[string]string{
		"":              "1.1.1.1:53",
		"8.8.8.8":       "8.8.8.8:53",
		"8.8.8.8:5353":  "8.8.8.8:5353",
		" 1.1.1.1 ":     "1.1.1.1:53",
		"9.9.9.9:53   ": "9.9.9.9:53",
	}
	for in, want := range cases {
		if got := normalizeResolver(in); got != want {
			t.Fatalf("normalizeResolver(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSupportedTypes(t *testing.T) {
	want := []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT"}
	got := SupportedTypes()
	if len(got) != len(want) {
		t.Fatalf("SupportedTypes() len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SupportedTypes()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
