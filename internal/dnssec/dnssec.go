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
	Domain           string   `json:"domain" yaml:"domain"`
	Resolver         string   `json:"resolver" yaml:"resolver"`
	ParentZone       string   `json:"parent_zone,omitempty" yaml:"parent_zone,omitempty"`
	Status           string   `json:"status" yaml:"status"`
	ChildDNSKEYCount int      `json:"child_dnskey_count" yaml:"child_dnskey_count"`
	ChildKSKCount    int      `json:"child_ksk_count" yaml:"child_ksk_count"`
	ChildRRSIGCount  int      `json:"child_rrsig_count" yaml:"child_rrsig_count"`
	ParentDSCount    int      `json:"parent_ds_count" yaml:"parent_ds_count"`
	MatchingDSCount  int      `json:"matching_ds_count" yaml:"matching_ds_count"`
	Findings         []string `json:"findings,omitempty" yaml:"findings,omitempty"`
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

	dnskeys, kskCount, rrsigs, err := queryDNSKEY(ctx, resolver, domain)
	if err != nil {
		return Report{}, err
	}
	dsRecords, matchingDS, err := queryDS(ctx, resolver, domain, dnskeys)
	if err != nil {
		return Report{}, err
	}

	report := Report{
		Domain:           domain,
		Resolver:         dnsquery.NormalizeResolver(resolver),
		ParentZone:       parent,
		ChildDNSKEYCount: len(dnskeys),
		ChildKSKCount:    kskCount,
		ChildRRSIGCount:  rrsigs,
		ParentDSCount:    len(dsRecords),
		MatchingDSCount:  matchingDS,
	}
	report.Status, report.Findings = classify(report)
	return report, nil
}

func queryDNSKEY(ctx context.Context, resolver, domain string) (dnskeys []*dns.DNSKEY, kskCount, rrsigs int, err error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
	msg.SetEdns0(1232, true)
	client := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := client.ExchangeContext(ctx, msg, normalizeResolver(resolver))
	if err != nil {
		return nil, 0, 0, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, 0, 0, fmt.Errorf("rcode %s", dns.RcodeToString[resp.Rcode])
	}
	for _, ans := range resp.Answer {
		switch rr := ans.(type) {
		case *dns.DNSKEY:
			dnskeys = append(dnskeys, rr)
			if rr.Flags&dns.SEP == dns.SEP {
				kskCount++
			}
		case *dns.RRSIG:
			if rr.TypeCovered == dns.TypeDNSKEY {
				rrsigs++
			}
		}
	}
	return dnskeys, kskCount, rrsigs, nil
}

func queryDS(ctx context.Context, resolver, domain string, dnskeys []*dns.DNSKEY) ([]*dns.DS, int, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeDS)
	msg.SetEdns0(1232, true)
	client := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := client.ExchangeContext(ctx, msg, normalizeResolver(resolver))
	if err != nil {
		return nil, 0, err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
	case dns.RcodeNameError:
		return nil, 0, fmt.Errorf("rcode %s", dns.RcodeToString[resp.Rcode])
	default:
		return nil, 0, fmt.Errorf("rcode %s", dns.RcodeToString[resp.Rcode])
	}
	var records []*dns.DS
	for _, ans := range resp.Answer {
		if ds, ok := ans.(*dns.DS); ok {
			records = append(records, ds)
		}
	}
	return records, matchingDS(records, dnskeys), nil
}

func classify(report Report) (string, []string) {
	var findings []string
	switch {
	case report.ChildDNSKEYCount == 0 && report.ParentDSCount == 0:
		return "unsigned", nil
	case report.ChildDNSKEYCount > 0 && report.ParentDSCount > 0 && report.ChildRRSIGCount > 0 && report.MatchingDSCount > 0:
		return "signed", nil
	case report.ParentDSCount > 0 && report.ChildDNSKEYCount == 0:
		findings = append(findings, "parent publishes DS but child returned no DNSKEY")
	case report.ChildDNSKEYCount > 0 && report.ParentDSCount == 0:
		findings = append(findings, "child publishes DNSKEY but parent returned no DS")
	case report.ChildDNSKEYCount > 0 && report.ParentDSCount > 0 && report.ChildRRSIGCount == 0:
		findings = append(findings, "child returned DNSKEY but no RRSIG covering the DNSKEY RRset")
	case report.ChildDNSKEYCount > 0 && report.ParentDSCount > 0 && report.MatchingDSCount == 0:
		findings = append(findings, "parent DS set does not match any child DNSKEY")
	default:
		findings = append(findings, "DNSSEC state is incomplete or inconsistent")
	}
	return "broken", findings
}

func matchingDS(parent []*dns.DS, dnskeys []*dns.DNSKEY) int {
	if len(parent) == 0 || len(dnskeys) == 0 {
		return 0
	}
	seen := make(map[string]bool)
	count := 0
	for _, key := range dnskeys {
		for _, ds := range parent {
			gen := key.ToDS(ds.DigestType)
			if gen == nil {
				continue
			}
			if gen.KeyTag == ds.KeyTag &&
				gen.Algorithm == ds.Algorithm &&
				gen.DigestType == ds.DigestType &&
				strings.EqualFold(gen.Digest, ds.Digest) {
				id := fmt.Sprintf("%d/%d/%d/%s", ds.KeyTag, ds.Algorithm, ds.DigestType, strings.ToUpper(ds.Digest))
				if !seen[id] {
					seen[id] = true
					count++
				}
			}
		}
	}
	return count
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
