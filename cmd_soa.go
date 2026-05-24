package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"dnsops/internal/dnsquery"
	"dnsops/internal/rawdns"
)

func cmdSOA(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"--resolver": true})
	fs := flag.NewFlagSet("soa", flag.ExitOnError)
	resolver := fs.String("resolver", defaultResolver(), "DNS resolver to query")
	jsonOut := fs.Bool("json", false, "emit JSON")
	_ = fs.Parse(args)
	if len(fs.Args()) != 1 {
		fatal("usage: dnsops soa <zone> [--resolver IP:PORT] [--json]")
	}
	zone := fs.Arg(0)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	soa, err := rawdns.LookupSOA(ctx, *resolver, zone)
	if err != nil {
		fatal(err.Error())
	}
	if *jsonOut {
		printJSON(struct {
			Resolver string           `json:"resolver"`
			SOA      rawdns.SOAResult `json:"soa"`
		}{Resolver: dnsquery.NormalizeResolver(*resolver), SOA: soa})
		return
	}
	fmt.Printf("%s  SOA\n", soa.Zone)
	fmt.Printf("resolver: %s\n\n", dnsquery.NormalizeResolver(*resolver))
	fmt.Printf("  ttl:     %d\n", soa.TTL)
	fmt.Printf("  ns:      %s\n", soa.NS)
	fmt.Printf("  mbox:    %s\n", soa.MBox)
	fmt.Printf("  serial:  %d\n", soa.Serial)
	fmt.Printf("  refresh: %d\n", soa.Refresh)
	fmt.Printf("  retry:   %d\n", soa.Retry)
	fmt.Printf("  expire:  %d\n", soa.Expire)
	fmt.Printf("  minttl:  %d\n", soa.MinTTL)
}
