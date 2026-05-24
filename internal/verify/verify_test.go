package verify

import "testing"

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
}

func TestMatchCheck(t *testing.T) {
	if !matchCheck(Check{Values: []string{"b", "a"}}, []string{"a", "b"}) {
		t.Fatal("exact values should match irrespective of order")
	}
	if matchCheck(Check{Values: []string{"a"}}, []string{"b"}) {
		t.Fatal("different exact values must not match")
	}
	if !matchCheck(Check{Contains: []string{"v=DMARC1", "p=reject"}}, []string{"v=DMARC1; p=reject; rua=mailto:x"}) {
		t.Fatal("contains fragments should match")
	}
	if matchCheck(Check{Contains: []string{"v=DMARC1", "p=reject"}}, []string{"v=DMARC1", "p=reject"}) {
		t.Fatal("fragments split across records must not match")
	}
	if matchCheck(Check{Contains: []string{"missing"}}, []string{"hello"}) {
		t.Fatal("missing fragment should fail")
	}
}
