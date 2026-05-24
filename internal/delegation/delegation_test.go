package delegation

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"dnsops/internal/dnsquery"
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

func TestInBailiwick(t *testing.T) {
	if !inBailiwick("example.com", "ns1.example.com") {
		t.Fatal("expected in-bailiwick nameserver")
	}
	if inBailiwick("example.com", "ns1.example.net") {
		t.Fatal("out-of-bailiwick nameserver should not require glue")
	}
}

func TestGlueConsistent(t *testing.T) {
	if !glueConsistent([]NSCheck{{GlueExpected: true, Glue: []string{"192.0.2.10"}}}) {
		t.Fatal("present glue should be consistent")
	}
	if glueConsistent([]NSCheck{{GlueExpected: true, GlueMissing: true}}) {
		t.Fatal("missing glue should not be consistent")
	}
}

func TestPossibleLame(t *testing.T) {
	if !possibleLame([]NSCheck{{PossibleLame: true}}) {
		t.Fatal("expected possible lame=true")
	}
	if possibleLame([]NSCheck{{PossibleLame: false}}) {
		t.Fatal("expected possible lame=false")
	}
}

func TestNameserverAddressErrors(t *testing.T) {
	oldQuery := dnsqueryQuery
	defer func() { dnsqueryQuery = oldQuery }()

	dnsqueryQuery = func(ctx context.Context, resolver, name, rrType string) (dnsquery.Result, error) {
		switch rrType {
		case "A":
			return dnsquery.Result{}, nil
		case "AAAA":
			return dnsquery.Result{}, nil
		default:
			return dnsquery.Result{}, fmt.Errorf("unexpected type %s", rrType)
		}
	}
	errs := nameserverAddressErrors(context.Background(), "1.1.1.1:53", "ns1.example.com")
	if len(errs) != 1 || errs[0] != "no A/AAAA address records found for nameserver" {
		t.Fatalf("nameserverAddressErrors() = %v", errs)
	}

	dnsqueryQuery = func(ctx context.Context, resolver, name, rrType string) (dnsquery.Result, error) {
		if rrType == "A" {
			return dnsquery.Result{}, fmt.Errorf("timeout")
		}
		return dnsquery.Result{Values: []string{"2001:db8::53"}}, nil
	}
	errs = nameserverAddressErrors(context.Background(), "1.1.1.1:53", "ns1.example.com")
	if len(errs) != 1 || errs[0] != "A lookup failed: timeout" {
		t.Fatalf("nameserverAddressErrors() partial failure = %v", errs)
	}
}

func TestAddressReachabilityBroken(t *testing.T) {
	if addressReachabilityBroken(nil) {
		t.Fatal("nil errors should not mean broken reachability")
	}
	if addressReachabilityBroken([]string{"A lookup failed: timeout"}) {
		t.Fatal("single-family failure should not mean broken reachability")
	}
	if !addressReachabilityBroken([]string{"A lookup failed: timeout", "AAAA lookup failed: timeout"}) {
		t.Fatal("both family failures should mean broken reachability")
	}
	if !addressReachabilityBroken([]string{"no A/AAAA address records found for nameserver"}) {
		t.Fatal("missing both address families should mean broken reachability")
	}
}
