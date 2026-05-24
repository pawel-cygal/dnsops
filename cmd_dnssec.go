package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"dnsops/internal/dnssec"
)

func cmdDNSSEC(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"--resolver": true})
	fs := flag.NewFlagSet("dnssec", flag.ExitOnError)
	resolver := fs.String("resolver", "1.1.1.1:53", "DNS resolver to query")
	jsonOut := fs.Bool("json", false, "emit JSON")
	_ = fs.Parse(args)
	if len(fs.Args()) != 1 {
		fatal("usage: dnsops dnssec <domain> [--resolver IP:PORT] [--json]")
	}
	domain := fs.Arg(0)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	report, err := dnssec.Run(ctx, *resolver, domain)
	if err != nil {
		fatal(err.Error())
	}
	if *jsonOut {
		printJSON(report)
		if report.Status == "broken" {
			exitCode(1)
		}
		return
	}

	fmt.Printf("%s  dnssec report\n", report.Domain)
	fmt.Printf("resolver: %s\n", report.Resolver)
	if report.ParentZone != "" {
		fmt.Printf("parent zone: %s\n", report.ParentZone)
	}
	fmt.Printf("status: %s\n", report.Status)
	fmt.Printf("child DNSKEY count: %d\n", report.ChildDNSKEYCount)
	fmt.Printf("child DNSKEY RRSIG count: %d\n", report.ChildRRSIGCount)
	fmt.Printf("parent DS count: %d\n", report.ParentDSCount)
	if len(report.Findings) > 0 {
		fmt.Println("\nfindings:")
		for _, finding := range report.Findings {
			fmt.Printf("  %s\n", finding)
		}
	}
	if report.Status == "broken" {
		exitCode(1)
	}
}
