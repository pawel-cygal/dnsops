package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"dnsops/internal/dnssec"
	"dnsops/internal/expiry"
	"dnsops/internal/mailcheck"
	"dnsops/internal/verify"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = oldStdout
	}()
	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(r)
		done <- string(data)
	}()
	fn()
	_ = w.Close()
	return <-done
}

func TestResolveStructuredOutput(t *testing.T) {
	format, err := resolveStructuredOutput(false, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if format != outputProm {
		t.Fatalf("expected prom output, got %q", format)
	}
	if _, err := resolveStructuredOutput(true, false, true); err == nil {
		t.Fatal("expected mutually exclusive output error")
	}
}

func TestPromLabelsEscapesAndSorts(t *testing.T) {
	got := promLabels(map[string]string{
		"b": "two",
		"a": "one",
		"z": "",
	})
	if got != `a="one",b="two"` {
		t.Fatalf("promLabels() = %q", got)
	}
}

func TestPrintVerifyProm(t *testing.T) {
	out := captureStdout(t, func() {
		printVerifyProm(verify.Report{
			File:     "checks.yaml",
			Resolver: "1.1.1.1:53",
			Matched:  1,
			Total:    2,
			Errors:   1,
			Results: []verify.CheckResult{
				{Name: "a.example.com", Type: "A", OK: true},
				{Name: "mx.example.com", Type: "MX", OK: false},
			},
		})
	})
	for _, want := range []string{
		"dnsops_verify_check_ok{file=\"checks.yaml\",name=\"a.example.com\",resolver=\"1.1.1.1:53\",type=\"A\"} 1",
		"dnsops_verify_check_ok{file=\"checks.yaml\",name=\"mx.example.com\",resolver=\"1.1.1.1:53\",type=\"MX\"} 0",
		"dnsops_verify_summary_errors{file=\"checks.yaml\",resolver=\"1.1.1.1:53\"} 1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("verify prom output missing %q:\n%s", want, out)
		}
	}
}

func TestPrintExpiryProm(t *testing.T) {
	out := captureStdout(t, func() {
		printExpiryProm([]expiry.Report{
			{Domain: "example.com", ExpiresAt: "2027-01-01T00:00:00Z", DaysRemaining: 30, Severity: "warn"},
			{Domain: "bad.example", Severity: "error", Error: "timeout"},
		})
	})
	for _, want := range []string{
		"dnsops_expiry_days_remaining{domain=\"example.com\"} 30",
		"dnsops_expiry_status{domain=\"example.com\",severity=\"warn\"} 1",
		"dnsops_expiry_error{domain=\"bad.example\"} 1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expiry prom output missing %q:\n%s", want, out)
		}
	}
}

func TestPrintDNSSECProm(t *testing.T) {
	out := captureStdout(t, func() {
		printDNSSECProm([]dnssec.Report{
			{
				Domain:           "example.com",
				Resolver:         "1.1.1.1:53",
				Status:           "signed",
				ChildDNSKEYCount: 2,
				ChildRRSIGCount:  1,
				ParentDSCount:    1,
			},
		})
	})
	for _, want := range []string{
		"dnsops_dnssec_status{domain=\"example.com\",status=\"signed\"} 1",
		"dnsops_dnssec_child_dnskey_count{domain=\"example.com\",resolver=\"1.1.1.1:53\"} 2",
		"dnsops_dnssec_parent_ds_count{domain=\"example.com\",resolver=\"1.1.1.1:53\"} 1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("dnssec prom output missing %q:\n%s", want, out)
		}
	}
}

func TestPrintMailProm(t *testing.T) {
	out := captureStdout(t, func() {
		printMailProm([]mailcheck.Report{
			{
				Domain:   "example.com",
				Resolver: "1.1.1.1:53",
				MX:       []string{"10 mx.example.com."},
				SPF:      []string{"v=spf1 -all"},
				DMARC:    []string{"v=DMARC1; p=reject"},
				DKIM: []mailcheck.DKIMRow{
					{Selector: "default", Values: []string{"v=DKIM1; p=abc"}},
					{Selector: "google", Error: "NXDOMAIN"},
				},
				Warnings: 1,
			},
		})
	})
	for _, want := range []string{
		"dnsops_mail_warnings{domain=\"example.com\",resolver=\"1.1.1.1:53\"} 1",
		"dnsops_mail_status{domain=\"example.com\",resolver=\"1.1.1.1:53\",status=\"warn\"} 1",
		"dnsops_mail_record_present{domain=\"example.com\",record=\"mx\",resolver=\"1.1.1.1:53\"} 1",
		"dnsops_mail_dkim_selector_ok{domain=\"example.com\",resolver=\"1.1.1.1:53\",selector=\"default\"} 1",
		"dnsops_mail_dkim_selector_ok{domain=\"example.com\",resolver=\"1.1.1.1:53\",selector=\"google\"} 0",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("mail prom output missing %q:\n%s", want, out)
		}
	}
}
