package delegation

import (
	"reflect"
	"testing"

	"dnsops/internal/rawdns"
)

func TestSOASerialConsistent(t *testing.T) {
	if !soaSerialConsistent([]NSCheck{
		{SOA: &rawdns.SOAResult{Serial: 1}},
		{SOA: &rawdns.SOAResult{Serial: 1}},
	}) {
		t.Fatal("same serials should be consistent")
	}
	if soaSerialConsistent([]NSCheck{
		{SOA: &rawdns.SOAResult{Serial: 1}},
		{SOA: &rawdns.SOAResult{Serial: 2}},
	}) {
		t.Fatal("different serials should not be consistent")
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
	got, err = parentZone("app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got != "example.com" {
		t.Fatalf("parentZone(app.example.com) = %q", got)
	}
	if _, err := parentZone("com"); err == nil {
		t.Fatal("single-label zone should fail")
	}
}

func TestStringSlicesEqualSortedInputs(t *testing.T) {
	a := sortedCopy([]string{"b", "a"})
	b := sortedCopy([]string{"a", "b"})
	if !reflect.DeepEqual(a, b) || !stringSlicesEqual(a, b) {
		t.Fatal("sortedCopy/stringSlicesEqual should treat the same set equally")
	}
}

func TestChildNSConsistent(t *testing.T) {
	if !childNSConsistent([]NSCheck{
		{NS: []string{"ns1.example.net", "ns2.example.net"}},
		{NS: []string{"ns2.example.net", "ns1.example.net"}},
	}) {
		t.Fatal("same child NS sets should be consistent")
	}
	if childNSConsistent([]NSCheck{
		{NS: []string{"ns1.example.net", "ns2.example.net"}},
		{NS: []string{"ns1.example.net"}},
	}) {
		t.Fatal("different child NS sets should not be consistent")
	}
}

func TestMajorityNS(t *testing.T) {
	got := majorityNS([]NSCheck{
		{NS: []string{"ns1.example.net", "ns2.example.net"}},
		{NS: []string{"ns2.example.net", "ns1.example.net"}},
		{NS: []string{"ns3.example.net"}},
	})
	want := []string{"ns1.example.net", "ns2.example.net"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("majorityNS() = %v, want %v", got, want)
	}
}
