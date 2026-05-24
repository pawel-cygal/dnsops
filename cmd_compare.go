package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"dnsops/internal/authority"
	"dnsops/internal/compare"
	"dnsops/internal/dnsquery"
	"dnsops/internal/propagation"
)

func cmdCompare(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"--baseline": true, "--resolvers": true, "--interval": true})
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	baseline := fs.String("baseline", "1.1.1.1:53", "baseline resolver")
	resolverList := fs.String("resolvers", "", "comma-separated resolvers to compare against the baseline")
	authoritative := fs.Bool("authoritative", false, "compare recursive resolvers against the authoritative nameservers")
	watch := fs.Bool("watch", false, "rerun the check until interrupted")
	interval := fs.Duration("interval", 5*time.Second, "watch interval")
	untilOK := fs.Bool("until-ok", false, "in watch mode, stop automatically once the check is healthy")
	_ = fs.Parse(args)
	if len(fs.Args()) != 2 {
		fatal("usage: dnsops compare <name> <type> [--baseline ip:53] [--resolvers ip:53,ip:53] [--authoritative] [--json] [--watch] [--interval 5s] [--until-ok]")
	}
	name, rrType := fs.Arg(0), fs.Arg(1)
	watchCfg, err := normalizeWatchConfig(*watch, *untilOK, *interval)
	if err != nil {
		fatal(err.Error())
	}
	resolvers := propagation.DefaultResolvers
	if strings.TrimSpace(*resolverList) != "" {
		resolvers = splitCSV(*resolverList)
	}

	if *authoritative {
		runOnce := func() (authority.Report, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return authority.Run(ctx, *baseline, resolvers, name, rrType)
		}
		if watchCfg.Enabled {
			err := watchLoop(watchCfg, fmt.Sprintf("compare %s %s --authoritative", name, strings.ToUpper(rrType)), *jsonOut, func() (watchIteration, error) {
				report, err := runOnce()
				if err != nil {
					return watchIteration{}, err
				}
				return watchIteration{
					Result:  report,
					Healthy: authoritativeHealthy(report),
					Render: func() {
						renderAuthoritativeCompare(report, *baseline)
					},
				}, nil
			})
			if err != nil {
				fatal(err.Error())
			}
			return
		}
		report, err := runOnce()
		if err != nil {
			fatal(err.Error())
		}
		if *jsonOut {
			printJSON(report)
			if report.HealthyAuth != report.TotalAuth || report.HealthyRec != report.TotalRec {
				exitCode(1)
			}
			return
		}
		renderAuthoritativeCompare(report, *baseline)
		if report.HealthyAuth != report.TotalAuth || report.HealthyRec != report.TotalRec {
			exitCode(1)
		}
		return
	}

	runOnce := func() (compare.Report, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return compare.Run(ctx, *baseline, resolvers, name, rrType)
	}
	if watchCfg.Enabled {
		err := watchLoop(watchCfg, fmt.Sprintf("compare %s %s", name, strings.ToUpper(rrType)), *jsonOut, func() (watchIteration, error) {
			report, err := runOnce()
			if err != nil {
				return watchIteration{}, err
			}
			return watchIteration{
				Result:  report,
				Healthy: compareHealthy(report),
				Render: func() {
					renderCompare(report)
				},
			}, nil
		})
		if err != nil {
			fatal(err.Error())
		}
		return
	}
	report, err := runOnce()
	if err != nil {
		fatal(err.Error())
	}
	if *jsonOut {
		printJSON(report)
		if report.Healthy != report.Total {
			exitCode(1)
		}
		return
	}
	renderCompare(report)
	if report.Healthy != report.Total {
		exitCode(1)
	}
}

func renderAuthoritativeCompare(report authority.Report, baseline string) {
	fmt.Printf("%s  %s\n", report.Name, strings.ToUpper(report.Type))
	fmt.Printf("zone: %s\n", report.Zone)
	fmt.Printf("discovery resolver: %s\n", dnsquery.NormalizeResolver(baseline))
	if len(report.Expected) > 0 {
		fmt.Println("\nauthoritative answer:")
		for _, v := range report.Expected {
			fmt.Printf("  %s\n", v)
		}
	}
	fmt.Println("\nauthoritative nameservers:")
	for _, r := range report.Authoritative {
		status := "ok"
		detail := strings.Join(r.Values, ", ")
		if r.Error != "" {
			status = "error"
			detail = r.Error
		} else if !r.Matches {
			status = "diff"
		}
		fmt.Printf("  %-24s  %-5s  %s\n", r.Nameserver, status, detail)
	}
	fmt.Println("\nrecursive resolvers:")
	for _, r := range report.Resolvers {
		status := "ok"
		detail := strings.Join(r.Values, ", ")
		if r.Error != "" {
			status = "error"
			detail = r.Error
		} else if !r.Matches {
			status = "diff"
		}
		fmt.Printf("  %-16s  %-5s  %s\n", r.Resolver, status, detail)
	}
	fmt.Printf("\nsummary: auth %d/%d match, recursive %d/%d match, auth_consistent=%v\n",
		report.HealthyAuth, report.TotalAuth, report.HealthyRec, report.TotalRec, report.AuthConsistent)
}

func renderCompare(report compare.Report) {
	fmt.Printf("%s  %s\n", report.Name, strings.ToUpper(report.Type))
	fmt.Printf("baseline: %s\n", report.Baseline)
	if len(report.Expected) > 0 {
		fmt.Println()
		for _, v := range report.Expected {
			fmt.Printf("  %s\n", v)
		}
	}
	fmt.Println("\nresolvers:")
	for _, r := range report.Resolvers {
		status := "ok"
		detail := strings.Join(r.Values, ", ")
		if r.Error != "" {
			status = "error"
			detail = r.Error
		} else if !r.Matches {
			status = "diff"
		}
		fmt.Printf("  %-16s  %-5s  %s\n", r.Resolver, status, detail)
	}
	fmt.Printf("\nsummary: %d/%d match the baseline\n", report.Healthy, report.Total)
}
