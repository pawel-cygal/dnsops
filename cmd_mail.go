package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"dnsops/internal/mailcheck"
)

type multiString []string

func (m *multiString) String() string { return strings.Join(*m, ",") }

func (m *multiString) Set(v string) error {
	v = strings.TrimSpace(v)
	if v != "" {
		*m = append(*m, v)
	}
	return nil
}

func cmdMail(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"--resolver": true, "--selector": true, "--input": true})
	fs := flag.NewFlagSet("mail", flag.ExitOnError)
	resolver := fs.String("resolver", defaultResolver(), "DNS resolver to query")
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	promOut := fs.Bool("prom", false, "emit Prometheus text format")
	input := fs.String("input", "", "file with domains to check, one per line")
	var selectors multiString
	fs.Var(&selectors, "selector", "DKIM selector to check (repeatable)")
	_ = fs.Parse(args)
	if len(fs.Args()) == 0 && *input == "" {
		fatal("usage: dnsops mail <domain> [domain...] [--resolver IP:PORT] [--selector default] [--input path] [--json|--yaml|--prom]")
	}
	format, err := resolveStructuredOutput(*jsonOut, *yamlOut, *promOut)
	if err != nil {
		fatal(err.Error())
	}
	domains, err := mergeTargets(fs.Args(), *input)
	if err != nil {
		fatal(err.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	reports := make([]mailcheck.Report, 0, len(domains))
	hadErr := false
	for _, domain := range domains {
		report := mailcheck.Run(ctx, *resolver, domain, selectors)
		if report.Errors > 0 {
			hadErr = true
		}
		reports = append(reports, report)
	}

	switch format {
	case outputJSON:
		if len(reports) == 1 {
			printJSON(reports[0])
		} else {
			printJSON(reports)
		}
		if hadErr {
			exitCode(1)
		}
		return
	case outputYAML:
		if len(reports) == 1 {
			printYAML(reports[0])
		} else {
			printYAML(reports)
		}
		if hadErr {
			exitCode(1)
		}
		return
	case outputProm:
		printMailProm(reports)
		if hadErr {
			exitCode(1)
		}
		return
	}

	for _, report := range reports {
		renderMail(report)
	}
	if hadErr {
		exitCode(1)
	}
}

func renderMail(report mailcheck.Report) {
	fmt.Printf("%s  mail report\n", report.Domain)
	fmt.Printf("resolver: %s\n\n", report.Resolver)
	if len(report.MX) > 0 {
		fmt.Println("MX:")
		for _, mx := range report.MX {
			fmt.Printf("  %s\n", mx)
		}
		fmt.Println()
	}
	if len(report.SPF) > 0 {
		fmt.Println("SPF:")
		for _, spf := range report.SPF {
			fmt.Printf("  %s\n", spf)
		}
		if report.SPFEffectiveLookups > 0 {
			fmt.Printf("  effective lookups: %d\n", report.SPFEffectiveLookups)
		}
		fmt.Println()
	}
	if len(report.DMARC) > 0 {
		fmt.Println("DMARC:")
		for _, d := range report.DMARC {
			fmt.Printf("  %s\n", d)
		}
		fmt.Println()
	}
	if len(report.MTASTS) > 0 {
		fmt.Println("MTA-STS:")
		for _, row := range report.MTASTS {
			fmt.Printf("  %s\n", row)
		}
		fmt.Println()
	}
	if len(report.DKIM) > 0 {
		fmt.Println("DKIM:")
		for _, row := range report.DKIM {
			if row.Error != "" {
				fmt.Printf("  %s  warn  %s\n", row.Selector, row.Error)
				continue
			}
			fmt.Printf("  %s  ok\n", row.Selector)
		}
		fmt.Println()
	}
	if len(report.Findings) > 0 {
		fmt.Println("findings:")
		for _, f := range report.Findings {
			fmt.Printf("  %-5s  %-5s  %s\n", f.Severity, f.Scope, f.Message)
		}
		fmt.Println()
	}
	fmt.Printf("summary: %d error(s), %d warning(s)\n", report.Errors, report.Warnings)
	fmt.Println()
}
