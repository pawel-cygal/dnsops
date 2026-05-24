package mailcheck

import (
	"context"
	"fmt"
	"strings"

	"dnsops/internal/dnsquery"
)

var query = dnsquery.Query

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
	Domain              string    `json:"domain" yaml:"domain"`
	Resolver            string    `json:"resolver" yaml:"resolver"`
	MX                  []string  `json:"mx,omitempty" yaml:"mx,omitempty"`
	SPF                 []string  `json:"spf,omitempty" yaml:"spf,omitempty"`
	SPFEffectiveLookups int       `json:"spf_effective_lookups,omitempty" yaml:"spf_effective_lookups,omitempty"`
	DMARC               []string  `json:"dmarc,omitempty" yaml:"dmarc,omitempty"`
	MTASTS              []string  `json:"mta_sts,omitempty" yaml:"mta_sts,omitempty"`
	DKIM                []DKIMRow `json:"dkim,omitempty" yaml:"dkim,omitempty"`
	Findings            []Finding `json:"findings" yaml:"findings"`
	Errors              int       `json:"errors" yaml:"errors"`
	Warnings            int       `json:"warnings" yaml:"warnings"`
}

func Run(ctx context.Context, resolver, domain string, selectors []string) Report {
	report := Report{Domain: domain, Resolver: dnsquery.NormalizeResolver(resolver)}

	mxRes, mxErr := query(ctx, resolver, domain, "MX")
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

	txtRes, txtErr := query(ctx, resolver, domain, "TXT")
	if txtErr != nil {
		add(&report, "warn", "spf", txtErr.Error())
	} else {
		report.SPF = matchingTXT(txtRes.Values, "v=spf1")
		if len(report.SPF) == 0 {
			add(&report, "warn", "spf", "no SPF record found")
		}
		maxLookups := 0
		for _, spf := range report.SPF {
			n, warns := estimateSPFLookups(ctx, resolver, spf, map[string]bool{})
			if n > maxLookups {
				maxLookups = n
			}
			for _, warn := range warns {
				add(&report, "warn", "spf", warn)
			}
			if n > 10 {
				add(&report, "warn", "spf", fmt.Sprintf("SPF record may exceed 10 DNS lookups after include/redirect expansion (%d)", n))
			}
		}
		report.SPFEffectiveLookups = maxLookups
	}

	dmarcName := "_dmarc." + strings.TrimSuffix(domain, ".")
	dmarcRes, dmarcErr := query(ctx, resolver, dmarcName, "TXT")
	if dmarcErr != nil {
		add(&report, "warn", "dmarc", dmarcErr.Error())
	} else {
		report.DMARC = matchingTXT(dmarcRes.Values, "v=DMARC1")
		if len(report.DMARC) == 0 {
			add(&report, "warn", "dmarc", "no DMARC record found")
		}
	}

	mtaSTSName := "_mta-sts." + strings.TrimSuffix(domain, ".")
	mtaSTSRes, mtaSTSErr := query(ctx, resolver, mtaSTSName, "TXT")
	if mtaSTSErr != nil {
		add(&report, "warn", "mta-sts", mtaSTSErr.Error())
	} else {
		report.MTASTS = matchingTXT(mtaSTSRes.Values, "v=STSv1")
		if len(report.MTASTS) == 0 {
			add(&report, "warn", "mta-sts", "no MTA-STS TXT record found")
		} else if !hostHasAddress(ctx, resolver, "mta-sts."+strings.TrimSuffix(domain, ".")) {
			add(&report, "warn", "mta-sts", "mta-sts policy host has no A/AAAA answer")
		}
	}

	for _, sel := range selectors {
		name := fmt.Sprintf("%s._domainkey.%s", sel, strings.TrimSuffix(domain, "."))
		row := DKIMRow{Selector: sel}
		res, err := query(ctx, resolver, name, "TXT")
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

func estimateSPFLookups(ctx context.Context, resolver, spf string, seen map[string]bool) (int, []string) {
	count := countSPFLookups(spf)
	var warns []string
	for _, include := range spfIncludeTargets(spf) {
		key := "include:" + strings.ToLower(include)
		if seen[key] {
			continue
		}
		seen[key] = true
		res, err := query(ctx, resolver, include, "TXT")
		if err != nil {
			warns = append(warns, fmt.Sprintf("SPF include %s lookup failed: %v", include, err))
			continue
		}
		child := matchingTXT(res.Values, "v=spf1")
		if len(child) == 0 {
			warns = append(warns, fmt.Sprintf("SPF include %s returned no SPF record", include))
			continue
		}
		n, childWarns := estimateSPFLookups(ctx, resolver, child[0], seen)
		count += n
		warns = append(warns, childWarns...)
	}
	if redirect := spfRedirectTarget(spf); redirect != "" {
		key := "redirect:" + strings.ToLower(redirect)
		if !seen[key] {
			seen[key] = true
			res, err := query(ctx, resolver, redirect, "TXT")
			if err != nil {
				warns = append(warns, fmt.Sprintf("SPF redirect %s lookup failed: %v", redirect, err))
			} else {
				child := matchingTXT(res.Values, "v=spf1")
				if len(child) == 0 {
					warns = append(warns, fmt.Sprintf("SPF redirect %s returned no SPF record", redirect))
				} else {
					n, childWarns := estimateSPFLookups(ctx, resolver, child[0], seen)
					count += n
					warns = append(warns, childWarns...)
				}
			}
		}
	}
	return count, warns
}

func spfIncludeTargets(spf string) []string {
	var out []string
	for _, field := range strings.Fields(strings.ToLower(spf)) {
		if strings.HasPrefix(field, "include:") {
			target := strings.TrimSpace(strings.TrimPrefix(field, "include:"))
			if target != "" {
				out = append(out, target)
			}
		}
	}
	return out
}

func spfRedirectTarget(spf string) string {
	for _, field := range strings.Fields(strings.ToLower(spf)) {
		if strings.HasPrefix(field, "redirect=") {
			target := strings.TrimSpace(strings.TrimPrefix(field, "redirect="))
			if target != "" {
				return target
			}
		}
	}
	return ""
}

func mxHost(mx string) string {
	parts := strings.Fields(mx)
	if len(parts) != 2 {
		return ""
	}
	return strings.TrimSuffix(parts[1], ".")
}

func hostHasAddress(ctx context.Context, resolver, host string) bool {
	if res, err := query(ctx, resolver, host, "A"); err == nil && len(res.Values) > 0 {
		return true
	}
	if res, err := query(ctx, resolver, host, "AAAA"); err == nil && len(res.Values) > 0 {
		return true
	}
	return false
}
