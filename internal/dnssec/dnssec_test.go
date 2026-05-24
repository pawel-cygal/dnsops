package dnssec

import (
	"testing"

	"github.com/miekg/dns"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name   string
		report Report
		want   string
	}{
		{"unsigned", Report{}, "unsigned"},
		{"signed", Report{ChildDNSKEYCount: 2, ChildRRSIGCount: 1, ParentDSCount: 1, MatchingDSCount: 1}, "signed"},
		{"broken-missing-dnskey", Report{ParentDSCount: 1}, "broken"},
		{"broken-missing-ds", Report{ChildDNSKEYCount: 1}, "broken"},
		{"broken-missing-rrsig", Report{ChildDNSKEYCount: 1, ParentDSCount: 1}, "broken"},
		{"broken-ds-mismatch", Report{ChildDNSKEYCount: 1, ChildRRSIGCount: 1, ParentDSCount: 1, MatchingDSCount: 0}, "broken"},
	}
	for _, tc := range cases {
		got, _ := classify(tc.report)
		if got != tc.want {
			t.Fatalf("%s: classify() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestParentZone(t *testing.T) {
	got, err := parentZone("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got != "com" {
		t.Fatalf("parentZone(example.com) = %q", got)
	}
	if _, err := parentZone("com"); err == nil {
		t.Fatal("single-label domain should fail")
	}
}

func TestMatchingDS(t *testing.T) {
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: "AwEAAcYJY4LqP4j8u0x5A9M5tVY2jN6QdA1R4dQx0w0R3K1yV9P1rL6m9v1M1g0Y4vX8u6WJ7QG2J1gX8f9dV3nL5h6z6uP1bQ2xL6mJ2i8K3wV4a9yN4mA7sL9tP2hJ5mN3bT6dW7mQ9xP2nJ4sV8xL5rT3mQ8vN1wY7qK6sP2dJ4mN7xV3aQ8pL1yT5kM2wQ7rN4xV6aP8",
	}
	match := key.ToDS(dns.SHA256)
	got := matchingDS([]*dns.DS{match}, []*dns.DNSKEY{key})
	if got != 1 {
		t.Fatalf("matchingDS() = %d, want 1", got)
	}
	got = matchingDS([]*dns.DS{{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 300}, KeyTag: 1, Algorithm: dns.RSASHA256, DigestType: dns.SHA256, Digest: "DEADBEEF"}}, []*dns.DNSKEY{key})
	if got != 0 {
		t.Fatalf("matchingDS() mismatch = %d, want 0", got)
	}
}
