package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"dnsops/internal/expiry"
)

func cmdExpiry(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"--warn-days": true, "--critical-days": true})
	fs := flag.NewFlagSet("expiry", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	warnDays := fs.Int("warn-days", 60, "warning threshold in days")
	criticalDays := fs.Int("critical-days", 14, "critical threshold in days")
	_ = fs.Parse(args)
	if len(fs.Args()) < 1 {
		fatal("usage: dnsops expiry <domain> [domain...] [--warn-days 60] [--critical-days 14] [--json]")
	}
	domains := fs.Args()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	reports := make([]expiry.Report, 0, len(domains))
	hadErr := false
	for _, domain := range domains {
		rep, err := expiry.Lookup(ctx, nil, domain, *warnDays, *criticalDays)
		if err != nil {
			hadErr = true
			if *jsonOut {
				reports = append(reports, expiry.Report{
					Domain:   strings.TrimSpace(domain),
					Severity: "error",
					RDAPURL:  "https://rdap.org/domain/" + strings.TrimSpace(domain),
					Error:    err.Error(),
				})
				continue
			}
			fmt.Printf("%s  error  %v\n", domain, err)
			continue
		}
		reports = append(reports, rep)
		if rep.Severity == "critical" {
			hadErr = true
		}
	}
	if *jsonOut {
		printJSON(reports)
		if hadErr {
			exitCode(1)
		}
		return
	}
	for _, rep := range reports {
		fmt.Printf("%s\n", rep.Domain)
		if rep.Registrar != "" {
			fmt.Printf("  registrar: %s\n", rep.Registrar)
		}
		if rep.ExpiresAt != "" {
			fmt.Printf("  expires_at: %s\n", rep.ExpiresAt)
			fmt.Printf("  days_remaining: %d\n", rep.DaysRemaining)
			fmt.Printf("  severity: %s\n", rep.Severity)
		}
		if len(rep.Statuses) > 0 {
			fmt.Printf("  statuses: %s\n", strings.Join(rep.Statuses, ", "))
		}
		if len(rep.Nameservers) > 0 {
			fmt.Printf("  nameservers: %s\n", strings.Join(rep.Nameservers, ", "))
		}
		fmt.Println()
	}
	if hadErr {
		exitCode(1)
	}
}
