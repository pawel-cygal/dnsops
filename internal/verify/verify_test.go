package verify

import (
	"testing"

	"dnsops/internal/rawdns"
)

func TestValidateCheck(t *testing.T) {
	if err := validateCheck(Check{Name: "a", Type: "A", Values: []string{"1.1.1.1"}}); err != nil {
		t.Fatalf("valid check rejected: %v", err)
	}
	if err := validateCheck(Check{}); err == nil {
		t.Fatal("empty check should fail")
	}
	if err := validateCheck(Check{Name: "a", Type: "TXT", Values: []string{"x"}, Contains: []string{"y"}}); err == nil {
		t.Fatal("values+contains should fail")
	}
	if err := validateCheck(Check{Name: "a", Type: "TXT", Regex: "["}); err == nil {
		t.Fatal("invalid regex should fail")
	}
	if err := validateCheck(Check{Name: "a", Type: "A", MustExist: true, MustNotExist: true}); err == nil {
		t.Fatal("must_exist + must_not_exist should fail")
	}
	if err := validateCheck(Check{Name: "a", Type: "A", MinTTL: 500, MaxTTL: 100}); err == nil {
		t.Fatal("min_ttl > max_ttl should fail")
	}
}

func TestMatchCheck(t *testing.T) {
	if !matchCheck(Check{Values: []string{"b", "a"}}, []rawdns.Record{{Data: "a"}, {Data: "b"}}) {
		t.Fatal("exact values should match irrespective of order")
	}
	if matchCheck(Check{Values: []string{"a"}}, []rawdns.Record{{Data: "b"}}) {
		t.Fatal("different exact values must not match")
	}
	if !matchCheck(Check{Contains: []string{"v=DMARC1", "p=reject"}}, []rawdns.Record{{Data: "v=DMARC1; p=reject; rua=mailto:x"}}) {
		t.Fatal("contains fragments should match")
	}
	if matchCheck(Check{Contains: []string{"v=DMARC1", "p=reject"}}, []rawdns.Record{{Data: "v=DMARC1"}, {Data: "p=reject"}}) {
		t.Fatal("fragments split across records must not match")
	}
	if matchCheck(Check{Contains: []string{"missing"}}, []rawdns.Record{{Data: "hello"}}) {
		t.Fatal("missing fragment should fail")
	}
	if !matchCheck(Check{Regex: `^v=spf1 .* -all$`}, []rawdns.Record{{Data: "v=spf1 include:_spf.example.com -all"}}) {
		t.Fatal("regex should match record")
	}
	if matchCheck(Check{Regex: `^nope$`}, []rawdns.Record{{Data: "hello"}}) {
		t.Fatal("regex mismatch should fail")
	}
	if !matchCheck(Check{MustExist: true}, []rawdns.Record{{Data: "1.1.1.1"}}) {
		t.Fatal("must_exist should pass on existing record")
	}
	if matchCheck(Check{MustExist: true}, nil) {
		t.Fatal("must_exist should fail on missing record")
	}
	if !matchCheck(Check{MustNotExist: true}, nil) {
		t.Fatal("must_not_exist should pass on missing record")
	}
	if matchCheck(Check{MustNotExist: true}, []rawdns.Record{{Data: "1.1.1.1"}}) {
		t.Fatal("must_not_exist should fail on existing record")
	}
	if !matchCheck(Check{Values: []string{"1.1.1.1"}, MinTTL: 60, MaxTTL: 300}, []rawdns.Record{{Data: "1.1.1.1", TTL: 120}}) {
		t.Fatal("TTL-bounded exact value should pass")
	}
	if matchCheck(Check{Values: []string{"1.1.1.1"}, MinTTL: 60}, []rawdns.Record{{Data: "1.1.1.1", TTL: 30}}) {
		t.Fatal("min_ttl should fail when record TTL is too low")
	}
	if matchCheck(Check{Values: []string{"1.1.1.1"}, MaxTTL: 60}, []rawdns.Record{{Data: "1.1.1.1", TTL: 120}}) {
		t.Fatal("max_ttl should fail when record TTL is too high")
	}
}
