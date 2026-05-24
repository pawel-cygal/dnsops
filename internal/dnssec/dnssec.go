package dnssec

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"dnsops/internal/dnsquery"

	"github.com/miekg/dns"
)

type Report struct {
	Domain           string   `json:"domain"`
	Resolver         string   `json:"resolver"`
	ParentZone       string   `json:"parent_zone,omitempty"`
	Status           string   `json:"status"`
	ChildDNSKEYCount int      `json:"child_dnskey_count"`
	ChildRRSIGCount  int      `json:"child_rrsig_count"`
	ParentDSCount    int      `json:"parent_ds_count"`
	Findings         []string `json:"findings,omitempty"`
}

func Run(ctx context.Context, resolver, domain string) (Report, error) {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		return Report{}, fmt.Errorf("domain is required")
	}
	parent, err := parentZone(domain)
	if err != nil {
		return Report{}, err
	}

	dnskeys, rrsigs, err := queryDNSKEY(ctx, resolver, domain)
	if err != nil {
		return Report{}, err
	}
	dsRecords, err := queryDS(ctx, resolver, domain)
	if err != nil {
		return Report{}, err
	}

	report := Report{
		Domain:           domain,
		Resolver:         dnsquery.NormalizeResolver(resolver),
		ParentZone:       parent,
		ChildDNSKEYCount: dnskeys,
		ChildRRSIGCount:  rrsigs,
		ParentDSCount:    dsRecords,
	}
	report.Status, report.Findings = classify(report)
	return report, nil
}

func queryDNSKEY(ctx context.Context, resolver, domain string) (dnskeys, rrsigs int, err error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
	msg.SetEdns0(1232, true)
	client := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := client.ExchangeContext(ctx, msg, normalizeResolver(resolver))
	if err != nil {
		return 0, 0, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return 0, 0, fmt.Errorf("rcode %s", dns.RcodeToString[resp.Rcode])
	}
	for _, ans := range resp.Answer {
		switch rr := ans.(type) {
		case *dns.DNSKEY:
			dnskeys++
		case *dns.RRSIG:
			if rr.TypeCovered == dns.TypeDNSKEY {
				rrsigs++
			}
		}
	}
	return dnskeys, rrsigs, nil
}

func queryDS(ctx context.Context, resolver, domain string) (int, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeDS)
	msg.SetEdns0(1232, true)
	client := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := client.ExchangeContext(ctx, msg, normalizeResolver(resolver))
	if err != nil {
		return 0, err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
	case dns.RcodeNameError:
		return 0, fmt.Errorf("rcode %s", dns.RcodeToString[resp.Rcode])
	default:
		return 0, fmt.Errorf("rcode %s", dns.RcodeToString[resp.Rcode])
	}
	count := 0
	for _, ans := range resp.Answer {
		if _, ok := ans.(*dns.DS); ok {
			count++
		}
	}
	return count, nil
}

func classify(report Report) (string, []string) {
	var findings []string
	switch {
	case report.ChildDNSKEYCount == 0 && report.ParentDSCount == 0:
		return "unsigned", nil
	case report.ChildDNSKEYCount > 0 && report.ParentDSCount > 0 && report.ChildRRSIGCount > 0:
		return "signed", nil
	case report.ParentDSCount > 0 && report.ChildDNSKEYCount == 0:
		findings = append(findings, "parent publishes DS but child returned no DNSKEY")
	case report.ChildDNSKEYCount > 0 && report.ParentDSCount == 0:
		findings = append(findings, "child publishes DNSKEY but parent returned no DS")
	case report.ChildDNSKEYCount > 0 && report.ParentDSCount > 0 && report.ChildRRSIGCount == 0:
		findings = append(findings, "child returned DNSKEY but no RRSIG covering the DNSKEY RRset")
	default:
		findings = append(findings, "DNSSEC state is incomplete or inconsistent")
	}
	return "broken", findings
}

func parentZone(zone string) (string, error) {
	parts := strings.Split(zone, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("domain %q has no parent zone", zone)
	}
	return strings.Join(parts[1:], "."), nil
}

func normalizeResolver(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "1.1.1.1:53"
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, "53")
}
