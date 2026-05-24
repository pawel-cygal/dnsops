package mailcheck

import (
	"context"
	"fmt"
	"strings"

	"dnsops/internal/dnsquery"
)

type Finding struct {
	Severity string `json:"severity" yaml:"severity"`
	Scope    string `json:"scope" yaml:"scope"`
	Message  string `json:"message" yaml:"message"`
}

type DKIMRow struct {
	Selector string   `json:"selector" yaml:"selector"`
	Values   []string `json:"values,omitempty" yaml:"values,omitempty"`
	Error    string   `json:"error,omitempty" yaml:"error,omitempty"`
}

type Report struct {
	Domain   string    `json:"domain" yaml:"domain"`
	Resolver string    `json:"resolver" yaml:"resolver"`
	MX       []string  `json:"mx,omitempty" yaml:"mx,omitempty"`
	SPF      []string  `json:"spf,omitempty" yaml:"spf,omitempty"`
	DMARC    []string  `json:"dmarc,omitempty" yaml:"dmarc,omitempty"`
	DKIM     []DKIMRow `json:"dkim,omitempty" yaml:"dkim,omitempty"`
	Findings []Finding `json:"findings" yaml:"findings"`
	Errors   int       `json:"errors" yaml:"errors"`
	Warnings int       `json:"warnings" yaml:"warnings"`
}

func Run(ctx context.Context, resolver, domain string, selectors []string) Report {
	report := Report{Domain: domain, Resolver: dnsquery.NormalizeResolver(resolver)}

	mxRes, mxErr := dnsquery.Query(ctx, resolver, domain, "MX")
	if mxErr != nil {
		add(&report, "error", "mx", mxErr.Error())
	} else {
		report.MX = mxRes.Values
		if len(report.MX) == 0 {
			add(&report, "error", "mx", "no MX records found")
		}
		for _, mx := range report.MX {
			host := mxHost(mx)
			if host != "" && !hostHasAddress(ctx, resolver, host) {
				add(&report, "warn", "mx", fmt.Sprintf("MX host %s has no A/AAAA answer", host))
			}
		}
	}

	txtRes, txtErr := dnsquery.Query(ctx, resolver, domain, "TXT")
	if txtErr != nil {
		add(&report, "warn", "spf", txtErr.Error())
	} else {
		report.SPF = matchingTXT(txtRes.Values, "v=spf1")
		if len(report.SPF) == 0 {
			add(&report, "warn", "spf", "no SPF record found")
		}
		for _, spf := range report.SPF {
			if n := countSPFLookups(spf); n > 10 {
				add(&report, "warn", "spf", fmt.Sprintf("SPF record may exceed 10 DNS lookups (%d)", n))
			}
		}
	}

	dmarcName := "_dmarc." + strings.TrimSuffix(domain, ".")
	dmarcRes, dmarcErr := dnsquery.Query(ctx, resolver, dmarcName, "TXT")
	if dmarcErr != nil {
		add(&report, "warn", "dmarc", dmarcErr.Error())
	} else {
		report.DMARC = matchingTXT(dmarcRes.Values, "v=DMARC1")
		if len(report.DMARC) == 0 {
			add(&report, "warn", "dmarc", "no DMARC record found")
		}
	}

	for _, sel := range selectors {
		name := fmt.Sprintf("%s._domainkey.%s", sel, strings.TrimSuffix(domain, "."))
		row := DKIMRow{Selector: sel}
		res, err := dnsquery.Query(ctx, resolver, name, "TXT")
		if err != nil {
			row.Error = err.Error()
			add(&report, "warn", "dkim", fmt.Sprintf("selector %s: %v", sel, err))
		} else {
			row.Values = res.Values
			if len(row.Values) == 0 {
				add(&report, "warn", "dkim", fmt.Sprintf("selector %s: no TXT record found", sel))
			}
		}
		report.DKIM = append(report.DKIM, row)
	}

	return report
}

func add(r *Report, severity, scope, msg string) {
	r.Findings = append(r.Findings, Finding{Severity: severity, Scope: scope, Message: msg})
	switch severity {
	case "error":
		r.Errors++
	case "warn":
		r.Warnings++
	}
}

func matchingTXT(values []string, prefix string) []string {
	var out []string
	for _, v := range values {
		if strings.HasPrefix(strings.ToLower(v), strings.ToLower(prefix)) {
			out = append(out, v)
		}
	}
	return out
}

func countSPFLookups(spf string) int {
	var n int
	for _, field := range strings.Fields(strings.ToLower(spf)) {
		switch {
		case strings.HasPrefix(field, "include:"):
			n++
		case field == "a" || strings.HasPrefix(field, "a:"):
			n++
		case field == "mx" || strings.HasPrefix(field, "mx:"):
			n++
		case field == "ptr" || strings.HasPrefix(field, "ptr:"):
			n++
		case strings.HasPrefix(field, "exists:"):
			n++
		case strings.HasPrefix(field, "redirect="):
			n++
		}
	}
	return n
}

func mxHost(mx string) string {
	parts := strings.Fields(mx)
	if len(parts) != 2 {
		return ""
	}
	return strings.TrimSuffix(parts[1], ".")
}

func hostHasAddress(ctx context.Context, resolver, host string) bool {
	if res, err := dnsquery.Query(ctx, resolver, host, "A"); err == nil && len(res.Values) > 0 {
		return true
	}
	if res, err := dnsquery.Query(ctx, resolver, host, "AAAA"); err == nil && len(res.Values) > 0 {
		return true
	}
	return false
}
