package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"dnsops/internal/dnsquery"
	"dnsops/internal/dnssec"
)

func cmdDNSSEC(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"--resolver": true, "--input": true})
	fs := flag.NewFlagSet("dnssec", flag.ExitOnError)
	resolver := fs.String("resolver", defaultResolver(), "DNS resolver to query")
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	promOut := fs.Bool("prom", false, "emit Prometheus text format")
	input := fs.String("input", "", "file with domains to check, one per line")
	_ = fs.Parse(args)
	if len(fs.Args()) == 0 && *input == "" {
		fatal("usage: dnsops dnssec <domain> [domain...] [--resolver IP:PORT] [--input path] [--json|--yaml|--prom]")
	}
	format, err := resolveStructuredOutput(*jsonOut, *yamlOut, *promOut)
	if err != nil {
		fatal(err.Error())
	}
	domains, err := mergeTargets(fs.Args(), *input)
	if err != nil {
		fatal(err.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	reports := make([]dnssec.Report, 0, len(domains))
	hadErr := false
	for _, domain := range domains {
		report, err := dnssec.Run(ctx, *resolver, domain)
		if err != nil {
			hadErr = true
			report = dnssec.Report{
				Domain:   domain,
				Resolver: dnsquery.NormalizeResolver(*resolver),
				Status:   "error",
				Findings: []string{err.Error()},
			}
		}
		if report.Status == "broken" || report.Status == "error" {
			hadErr = true
		}
		reports = append(reports, report)
	}
	switch format {
	case outputJSON:
		printJSON(reports)
		if hadErr {
			exitCode(1)
		}
		return
	case outputYAML:
		printYAML(reports)
		if hadErr {
			exitCode(1)
		}
		return
	case outputProm:
		printDNSSECProm(reports)
		if hadErr {
			exitCode(1)
		}
		return
	}

	for _, report := range reports {
		fmt.Printf("%s  dnssec report\n", report.Domain)
		fmt.Printf("resolver: %s\n", report.Resolver)
		if report.ParentZone != "" {
			fmt.Printf("parent zone: %s\n", report.ParentZone)
		}
		fmt.Printf("status: %s\n", report.Status)
		fmt.Printf("child DNSKEY count: %d\n", report.ChildDNSKEYCount)
		fmt.Printf("child KSK count: %d\n", report.ChildKSKCount)
		fmt.Printf("child DNSKEY RRSIG count: %d\n", report.ChildRRSIGCount)
		fmt.Printf("parent DS count: %d\n", report.ParentDSCount)
		fmt.Printf("matching DS count: %d\n", report.MatchingDSCount)
		if len(report.Findings) > 0 {
			fmt.Println("\nfindings:")
			for _, finding := range report.Findings {
				fmt.Printf("  %s\n", finding)
			}
		}
		fmt.Println()
	}
	if hadErr {
		exitCode(1)
	}
}
