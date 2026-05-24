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
	args = normalizeFlagArgs(args, map[string]bool{"--resolver": true, "--selector": true})
	fs := flag.NewFlagSet("mail", flag.ExitOnError)
	resolver := fs.String("resolver", "1.1.1.1:53", "DNS resolver to query")
	jsonOut := fs.Bool("json", false, "emit JSON")
	var selectors multiString
	fs.Var(&selectors, "selector", "DKIM selector to check (repeatable)")
	_ = fs.Parse(args)
	if len(fs.Args()) != 1 {
		fatal("usage: dnsops mail <domain> [--resolver IP:PORT] [--selector default] [--json]")
	}
	domain := fs.Arg(0)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	report := mailcheck.Run(ctx, *resolver, domain, selectors)
	if *jsonOut {
		printJSON(report)
		if report.Errors > 0 {
			exitCode(1)
		}
		return
	}

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
		fmt.Println()
	}
	if len(report.DMARC) > 0 {
		fmt.Println("DMARC:")
		for _, d := range report.DMARC {
			fmt.Printf("  %s\n", d)
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
	if report.Errors > 0 {
		exitCode(1)
	}
}
