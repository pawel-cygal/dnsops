package rawdns

import "testing"

func TestParseType(t *testing.T) {
	if _, err := parseType("A"); err != nil {
		t.Fatal(err)
	}
	if _, err := parseType("PTR"); err != nil {
		t.Fatal(err)
	}
	if _, err := parseType("CAA"); err != nil {
		t.Fatal(err)
	}
	if _, err := parseType("BAD"); err == nil {
		t.Fatal("expected unsupported type error")
	}
}
