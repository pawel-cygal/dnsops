package dnsquery

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"dnsops/internal/rawdns"
)

var supportedTypes = []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT"}

type Result struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Resolver string   `json:"resolver"`
	Values   []string `json:"values"`
}

func SupportedTypes() []string {
	out := make([]string, len(supportedTypes))
	copy(out, supportedTypes)
	return out
}

func NormalizeResolver(addr string) string {
	return normalizeResolver(addr)
}

func Query(ctx context.Context, resolverAddr, name, rrType string) (Result, error) {
	rrType = strings.ToUpper(strings.TrimSpace(rrType))
	if !slices.Contains(supportedTypes, rrType) {
		return Result{}, fmt.Errorf("unsupported type %q (supported: %s)", rrType, strings.Join(supportedTypes, ", "))
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return Result{}, fmt.Errorf("name is required")
	}
	resolverAddr = normalizeResolver(resolverAddr)
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", resolverAddr)
		},
	}

	var values []string
	var err error
	switch rrType {
	case "A":
		values, err = lookupIPs(ctx, resolver, "ip4", name)
	case "AAAA":
		values, err = lookupIPs(ctx, resolver, "ip6", name)
	case "CNAME":
		var records []rawdns.Record
		records, err = rawdns.Query(ctx, resolverAddr, name, rrType)
		if err == nil {
			values = make([]string, 0, len(records))
			for _, rec := range records {
				values = append(values, rec.Data)
			}
			slices.Sort(values)
		}
	case "MX":
		values, err = lookupMX(ctx, resolver, name)
	case "NS":
		values, err = lookupNS(ctx, resolver, name)
	case "TXT":
		values, err = resolver.LookupTXT(ctx, name)
		if err == nil {
			slices.Sort(values)
		}
	}
	if err != nil {
		return Result{}, err
	}
	return Result{
		Name:     name,
		Type:     rrType,
		Resolver: resolverAddr,
		Values:   values,
	}, nil
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

func lookupIPs(ctx context.Context, r *net.Resolver, network, name string) ([]string, error) {
	ips, err := r.LookupIP(ctx, network, name)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	slices.Sort(out)
	return out, nil
}

func lookupMX(ctx context.Context, r *net.Resolver, name string) ([]string, error) {
	mxs, err := r.LookupMX(ctx, name)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(mxs))
	for _, mx := range mxs {
		out = append(out, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
	}
	slices.Sort(out)
	return out, nil
}

func lookupNS(ctx context.Context, r *net.Resolver, name string) ([]string, error) {
	nss, err := r.LookupNS(ctx, name)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(nss))
	for _, ns := range nss {
		out = append(out, ns.Host)
	}
	slices.Sort(out)
	return out, nil
}
