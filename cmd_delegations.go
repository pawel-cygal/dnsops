package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"dnsops/internal/delegation"
	"dnsops/internal/dnsquery"
)

func cmdDelegations(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"--resolver": true})
	fs := flag.NewFlagSet("delegations", flag.ExitOnError)
	resolver := fs.String("resolver", defaultResolver(), "resolver used to discover the delegation")
	jsonOut := fs.Bool("json", false, "emit JSON")
	_ = fs.Parse(args)
	if len(fs.Args()) != 1 {
		fatal("usage: dnsops delegations <zone> [--resolver IP:PORT] [--json]")
	}
	zone := fs.Arg(0)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	report, err := delegation.Run(ctx, *resolver, zone)
	if err != nil {
		fatal(err.Error())
	}
	if *jsonOut {
		printJSON(report)
		if !delegationHealthy(report) {
			exitCode(1)
		}
		return
	}
	fmt.Printf("%s  delegation report\n", report.Zone)
	fmt.Printf("discovery resolver: %s\n\n", dnsquery.NormalizeResolver(*resolver))
	if report.ParentZone != "" && len(report.ParentNS) > 0 {
		fmt.Printf("parent zone: %s\n", report.ParentZone)
		fmt.Println("parent authoritative nameservers:")
		for _, ns := range report.ParentNS {
			fmt.Printf("  %s\n", ns)
		}
		fmt.Println()
	}
	if len(report.ParentDelegation) > 0 {
		fmt.Println("parent delegation:")
		for _, ns := range report.ParentDelegation {
			fmt.Printf("  %s\n", ns)
		}
		fmt.Println()
	}
	if len(report.ParentChecks) > 0 {
		fmt.Println("parent nameserver checks:")
		for _, c := range report.ParentChecks {
			line := c.Nameserver
			if c.Error != "" {
				fmt.Printf("  %-24s  error  %s\n", line, c.Error)
				continue
			}
			fmt.Printf("  %-24s  ns=%s\n", line, strings.Join(c.NS, ", "))
		}
		fmt.Println()
	}
	if len(report.ChildApexNS) > 0 {
		fmt.Println("child apex NS:")
		for _, ns := range report.ChildApexNS {
			fmt.Printf("  %s\n", ns)
		}
		fmt.Println()
	}
	fmt.Println("child nameserver checks:")
	for _, c := range report.ChildChecks {
		line := c.Nameserver
		if c.Error != "" {
			fmt.Printf("  %-24s  error  %s\n", line, c.Error)
			if c.GlueExpected {
				if c.GlueMissing {
					fmt.Printf("  %-24s  glue   missing (in-bailiwick nameserver)\n", "")
				} else if len(c.Glue) > 0 {
					fmt.Printf("  %-24s  glue   %s\n", "", strings.Join(c.Glue, ", "))
				}
			}
			for _, reason := range c.LameReasons {
				fmt.Printf("  %-24s  hint   %s\n", "", reason)
			}
			continue
		}
		fmt.Printf("  %-24s  ns=%s", line, strings.Join(c.NS, ", "))
		if c.SOA != nil {
			fmt.Printf("  serial=%d", c.SOA.Serial)
		}
		fmt.Println()
		if c.GlueExpected {
			if c.GlueMissing {
				fmt.Printf("  %-24s  glue=missing\n", "")
			} else if len(c.Glue) > 0 {
				fmt.Printf("  %-24s  glue=%s\n", "", strings.Join(c.Glue, ", "))
			}
		}
		if c.PossibleLame {
			fmt.Printf("  %-24s  hint=possible lame delegation\n", "")
			for _, reason := range c.LameReasons {
				fmt.Printf("  %-24s  hint=%s\n", "", reason)
			}
		}
	}
	fmt.Printf("\nsummary: parent_matches_child=%v  child_ns_consistent=%v  soa_serial_consistent=%v  glue_consistent=%v  possible_lame=%v\n",
		report.ParentMatchesChild, report.ChildNSConsistent, report.SOASerialConsistent, report.GlueConsistent, report.PossibleLame)
	if !delegationHealthy(report) {
		exitCode(1)
	}
}

func delegationHealthy(report delegation.Report) bool {
	return report.ParentMatchesChild &&
		report.ChildNSConsistent &&
		report.SOASerialConsistent &&
		report.GlueConsistent &&
		!report.PossibleLame
}
