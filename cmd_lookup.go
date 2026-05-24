package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"dnsops/internal/dnsquery"
	"dnsops/internal/rawdns"
)

func cmdLookup(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"--resolver": true})
	fs := flag.NewFlagSet("lookup", flag.ExitOnError)
	resolver := fs.String("resolver", "1.1.1.1:53", "DNS resolver to query")
	jsonOut := fs.Bool("json", false, "emit JSON")
	ttlOut := fs.Bool("ttl", false, "show TTL-aware answers via raw DNS queries")
	_ = fs.Parse(args)
	if len(fs.Args()) != 2 {
		fatal("usage: dnsops lookup <name> <type> [--resolver IP:PORT] [--json] [--ttl]")
	}
	name, rrType := fs.Arg(0), fs.Arg(1)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	if *ttlOut {
		records, err := rawdns.Query(ctx, *resolver, name, rrType)
		if err != nil {
			fatal(err.Error())
		}
		if *jsonOut {
			printJSON(struct {
				Name     string          `json:"name"`
				Type     string          `json:"type"`
				Resolver string          `json:"resolver"`
				Answers  []rawdns.Record `json:"answers"`
			}{
				Name:     name,
				Type:     rrType,
				Resolver: rawdnsResolver(*resolver),
				Answers:  records,
			})
			return
		}
		fmt.Printf("%s  %s\n", name, rrType)
		fmt.Printf("resolver: %s\n\n", rawdnsResolver(*resolver))
		for _, rec := range records {
			fmt.Printf("  %-5d %-5s %s\n", rec.TTL, rec.Type, rec.Data)
		}
		return
	}

	res, err := dnsquery.Query(ctx, *resolver, name, rrType)
	if err != nil {
		fatal(err.Error())
	}
	if *jsonOut {
		printJSON(res)
		return
	}

	fmt.Printf("%s  %s\n", res.Name, res.Type)
	fmt.Printf("resolver: %s\n", res.Resolver)
	if len(res.Values) == 0 {
		fmt.Println("(no answers)")
		return
	}
	fmt.Println()
	for _, v := range res.Values {
		fmt.Printf("  %s\n", v)
	}
}

func rawdnsResolver(addr string) string {
	return dnsquery.NormalizeResolver(addr)
}
