package rawdns

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Record struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  uint32 `json:"ttl"`
	Data string `json:"data"`
}

type SOAResult struct {
	Zone    string `json:"zone"`
	TTL     uint32 `json:"ttl"`
	NS      string `json:"ns"`
	MBox    string `json:"mbox"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	MinTTL  uint32 `json:"minttl"`
}

type DelegationResult struct {
	NS   []string            `json:"ns"`
	Glue map[string][]string `json:"glue,omitempty"`
}

func Query(ctx context.Context, resolver, name, rrType string) ([]Record, error) {
	qtype, err := parseType(rrType)
	if err != nil {
		return nil, err
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(strings.TrimSpace(name)), qtype)
	client := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := client.ExchangeContext(ctx, msg, normalizeResolver(resolver))
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("rcode %s", dns.RcodeToString[resp.Rcode])
	}
	out := make([]Record, 0, len(resp.Answer))
	for _, ans := range resp.Answer {
		if rec, ok := toRecord(ans); ok {
			out = append(out, rec)
		}
	}
	return out, nil
}

func LookupSOA(ctx context.Context, resolver, zone string) (SOAResult, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(strings.TrimSpace(zone)), dns.TypeSOA)
	client := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := client.ExchangeContext(ctx, msg, normalizeResolver(resolver))
	if err != nil {
		return SOAResult{}, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return SOAResult{}, fmt.Errorf("rcode %s", dns.RcodeToString[resp.Rcode])
	}
	for _, ans := range resp.Answer {
		if soa, ok := ans.(*dns.SOA); ok {
			return SOAResult{
				Zone:    strings.TrimSuffix(soa.Header().Name, "."),
				TTL:     soa.Header().Ttl,
				NS:      strings.TrimSuffix(soa.Ns, "."),
				MBox:    strings.TrimSuffix(soa.Mbox, "."),
				Serial:  soa.Serial,
				Refresh: soa.Refresh,
				Retry:   soa.Retry,
				Expire:  soa.Expire,
				MinTTL:  soa.Minttl,
			}, nil
		}
	}
	return SOAResult{}, fmt.Errorf("no SOA answer")
}

func LookupDelegation(ctx context.Context, resolver, zone string) (DelegationResult, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(strings.TrimSpace(zone)), dns.TypeNS)
	client := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := client.ExchangeContext(ctx, msg, normalizeResolver(resolver))
	if err != nil {
		return DelegationResult{}, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return DelegationResult{}, fmt.Errorf("rcode %s", dns.RcodeToString[resp.Rcode])
	}
	out := DelegationResult{
		NS: extractNS(resp.Answer, resp.Ns),
	}
	out.Glue = extractGlue(out.NS, resp.Extra)
	return out, nil
}

func parseType(rrType string) (uint16, error) {
	switch strings.ToUpper(strings.TrimSpace(rrType)) {
	case "A":
		return dns.TypeA, nil
	case "AAAA":
		return dns.TypeAAAA, nil
	case "CNAME":
		return dns.TypeCNAME, nil
	case "PTR":
		return dns.TypePTR, nil
	case "MX":
		return dns.TypeMX, nil
	case "NS":
		return dns.TypeNS, nil
	case "TXT":
		return dns.TypeTXT, nil
	case "CAA":
		return dns.TypeCAA, nil
	default:
		return 0, fmt.Errorf("unsupported type %q", rrType)
	}
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

func toRecord(rr dns.RR) (Record, bool) {
	h := rr.Header()
	rec := Record{
		Name: strings.TrimSuffix(h.Name, "."),
		Type: dns.TypeToString[h.Rrtype],
		TTL:  h.Ttl,
	}
	switch v := rr.(type) {
	case *dns.A:
		rec.Data = v.A.String()
	case *dns.AAAA:
		rec.Data = v.AAAA.String()
	case *dns.CNAME:
		rec.Data = strings.TrimSuffix(v.Target, ".")
	case *dns.PTR:
		rec.Data = strings.TrimSuffix(v.Ptr, ".")
	case *dns.MX:
		rec.Data = fmt.Sprintf("%d %s", v.Preference, strings.TrimSuffix(v.Mx, "."))
	case *dns.NS:
		rec.Data = strings.TrimSuffix(v.Ns, ".")
	case *dns.TXT:
		rec.Data = strings.Join(v.Txt, "")
	case *dns.CAA:
		rec.Data = fmt.Sprintf("%d %s %q", v.Flag, strings.ToLower(v.Tag), v.Value)
	case *dns.SOA:
		rec.Data = fmt.Sprintf("%s %s serial=%d", strings.TrimSuffix(v.Ns, "."), strings.TrimSuffix(v.Mbox, "."), v.Serial)
	default:
		return Record{}, false
	}
	return rec, true
}

func extractNS(sections ...[]dns.RR) []string {
	var out []string
	for _, section := range sections {
		for _, rr := range section {
			if ns, ok := rr.(*dns.NS); ok {
				out = append(out, strings.TrimSuffix(ns.Ns, "."))
			}
		}
	}
	return sortedUniqueStrings(out)
}

func extractGlue(nameservers []string, section []dns.RR) map[string][]string {
	if len(nameservers) == 0 {
		return nil
	}
	allowed := map[string]bool{}
	for _, ns := range nameservers {
		allowed[strings.TrimSuffix(strings.ToLower(ns), ".")] = true
	}
	out := map[string][]string{}
	for _, rr := range section {
		host := strings.TrimSuffix(strings.ToLower(rr.Header().Name), ".")
		if !allowed[host] {
			continue
		}
		switch v := rr.(type) {
		case *dns.A:
			out[host] = append(out[host], v.A.String())
		case *dns.AAAA:
			out[host] = append(out[host], v.AAAA.String())
		}
	}
	if len(out) == 0 {
		return nil
	}
	for host, ips := range out {
		out[host] = sortedUniqueStrings(ips)
	}
	return out
}

func sortedUniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	slices.Sort(out)
	j := 1
	for i := 1; i < len(out); i++ {
		if out[i] != out[i-1] {
			out[j] = out[i]
			j++
		}
	}
	return out[:j]
}
