package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"dnsops/internal/dnsquery"
	"dnsops/internal/rawdns"
)

func cmdCAA(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"--resolver": true})
	fs := flag.NewFlagSet("caa", flag.ExitOnError)
	resolver := fs.String("resolver", "1.1.1.1:53", "DNS resolver to query")
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	_ = fs.Parse(args)
	if len(fs.Args()) != 1 {
		fatal("usage: dnsops caa <domain> [--resolver IP:PORT] [--json|--yaml]")
	}
	format, err := resolveOutputFormat(*jsonOut, *yamlOut)
	if err != nil {
		fatal(err.Error())
	}
	domain := fs.Arg(0)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	records, err := rawdns.Query(ctx, *resolver, domain, "CAA")
	if err != nil {
		fatal(err.Error())
	}
	report := struct {
		Domain   string          `json:"domain" yaml:"domain"`
		Resolver string          `json:"resolver" yaml:"resolver"`
		Records  []rawdns.Record `json:"records" yaml:"records"`
	}{
		Domain:   domain,
		Resolver: dnsquery.NormalizeResolver(*resolver),
		Records:  records,
	}

	switch format {
	case outputJSON:
		printJSON(report)
	case outputYAML:
		printYAML(report)
	default:
		fmt.Printf("%s  CAA\n", report.Domain)
		fmt.Printf("resolver: %s\n\n", report.Resolver)
		if len(report.Records) == 0 {
			fmt.Println("(no CAA records)")
			return
		}
		rows := make([][]string, 0, len(report.Records))
		for _, rec := range report.Records {
			rows = append(rows, []string{fmt.Sprintf("%d", rec.TTL), rec.Data})
		}
		renderTable([]string{"ttl", "record"}, rows)
	}
}
