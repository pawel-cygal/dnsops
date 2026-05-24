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
	args = normalizeFlagArgs(args, map[string]bool{"--resolver": true, "--input": true})
	fs := flag.NewFlagSet("caa", flag.ExitOnError)
	resolver := fs.String("resolver", defaultResolver(), "DNS resolver to query")
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	input := fs.String("input", "", "file with domains to check, one per line")
	_ = fs.Parse(args)
	if len(fs.Args()) == 0 && *input == "" {
		fatal("usage: dnsops caa <domain> [domain...] [--resolver IP:PORT] [--input path] [--json|--yaml]")
	}
	format, err := resolveOutputFormat(*jsonOut, *yamlOut)
	if err != nil {
		fatal(err.Error())
	}
	domains, err := mergeTargets(fs.Args(), *input)
	if err != nil {
		fatal(err.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	type report struct {
		Domain   string          `json:"domain" yaml:"domain"`
		Resolver string          `json:"resolver" yaml:"resolver"`
		Records  []rawdns.Record `json:"records,omitempty" yaml:"records,omitempty"`
		Error    string          `json:"error,omitempty" yaml:"error,omitempty"`
	}
	reports := make([]report, 0, len(domains))
	hadErr := false
	for _, domain := range domains {
		records, err := rawdns.Query(ctx, *resolver, domain, "CAA")
		rep := report{
			Domain:   domain,
			Resolver: dnsquery.NormalizeResolver(*resolver),
		}
		if err != nil {
			rep.Error = err.Error()
			hadErr = true
		} else {
			rep.Records = records
		}
		reports = append(reports, rep)
	}

	switch format {
	case outputJSON:
		printJSON(reports)
	case outputYAML:
		printYAML(reports)
	default:
		for _, report := range reports {
			fmt.Printf("%s  CAA\n", report.Domain)
			fmt.Printf("resolver: %s\n\n", report.Resolver)
			if report.Error != "" {
				fmt.Printf("error: %s\n\n", report.Error)
				continue
			}
			if len(report.Records) == 0 {
				fmt.Println("(no CAA records)")
				fmt.Println()
				continue
			}
			rows := make([][]string, 0, len(report.Records))
			for _, rec := range report.Records {
				rows = append(rows, []string{fmt.Sprintf("%d", rec.TTL), rec.Data})
			}
			renderTable([]string{"ttl", "record"}, rows)
			fmt.Println()
		}
	}
	if hadErr {
		exitCode(1)
	}
}
