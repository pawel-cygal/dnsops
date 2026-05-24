package mailcheck

import (
	"context"
	"fmt"
	"testing"

	"dnsops/internal/dnsquery"
)

func TestCountSPFLookups(t *testing.T) {
	spf := "v=spf1 include:_spf.google.com include:mail.example.com a mx exists:%{i} redirect=_spf.example.com ~all"
	if got := countSPFLookups(spf); got != 6 {
		t.Fatalf("countSPFLookups() = %d, want 6", got)
	}
}

func TestMatchingTXT(t *testing.T) {
	values := []string{"v=spf1 include:_spf.example.com ~all", "google-site-verification=abc"}
	got := matchingTXT(values, "v=spf1")
	if len(got) != 1 || got[0] != values[0] {
		t.Fatalf("matchingTXT() = %v", got)
	}
}

func TestEstimateSPFLookupsRecursive(t *testing.T) {
	oldQuery := query
	defer func() { query = oldQuery }()

	query = func(ctx context.Context, resolver, name, rrType string) (dnsquery.Result, error) {
		if rrType != "TXT" {
			return dnsquery.Result{}, fmt.Errorf("unexpected type %s", rrType)
		}
		switch name {
		case "_spf.example.com":
			return dnsquery.Result{Values: []string{"v=spf1 include:_spf2.example.com -all"}}, nil
		case "_spf2.example.com":
			return dnsquery.Result{Values: []string{"v=spf1 a mx -all"}}, nil
		default:
			return dnsquery.Result{}, fmt.Errorf("unexpected name %s", name)
		}
	}

	got, warns := estimateSPFLookups(context.Background(), "1.1.1.1:53", "v=spf1 include:_spf.example.com ~all", map[string]bool{})
	if got != 4 {
		t.Fatalf("estimateSPFLookups() = %d, want 4", got)
	}
	if len(warns) != 0 {
		t.Fatalf("estimateSPFLookups() warnings = %v", warns)
	}
}

func TestRunAddsMTASTS(t *testing.T) {
	oldQuery := query
	defer func() { query = oldQuery }()

	query = func(ctx context.Context, resolver, name, rrType string) (dnsquery.Result, error) {
		switch rrType {
		case "MX":
			if name == "example.com" {
				return dnsquery.Result{Values: []string{"10 mx.example.com"}}, nil
			}
		case "TXT":
			switch name {
			case "example.com":
				return dnsquery.Result{Values: []string{"v=spf1 -all"}}, nil
			case "_dmarc.example.com":
				return dnsquery.Result{Values: []string{"v=DMARC1; p=reject"}}, nil
			case "_mta-sts.example.com":
				return dnsquery.Result{Values: []string{"v=STSv1; id=abc"}}, nil
			}
		case "A":
			switch name {
			case "mx.example.com", "mta-sts.example.com":
				return dnsquery.Result{Values: []string{"192.0.2.10"}}, nil
			}
		case "AAAA":
			return dnsquery.Result{}, nil
		}
		return dnsquery.Result{}, nil
	}

	report := Run(context.Background(), "1.1.1.1:53", "example.com", nil)
	if len(report.MTASTS) != 1 || report.MTASTS[0] != "v=STSv1; id=abc" {
		t.Fatalf("Run() MTA-STS = %v", report.MTASTS)
	}
	if report.SPFEffectiveLookups != 0 {
		t.Fatalf("Run() SPFEffectiveLookups = %d, want 0", report.SPFEffectiveLookups)
	}
}
