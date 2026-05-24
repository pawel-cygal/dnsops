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
	args = normalizeFlagArgs(args, map[string]bool{"--baseline": true, "--resolvers": true, "--profile": true, "--interval": true, "--timeout": true, "--max-iterations": true})
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	baseline := fs.String("baseline", defaultResolver(), "baseline resolver")
	resolverList := fs.String("resolvers", "", "comma-separated resolvers to compare against the baseline")
	var profiles multiString
	fs.Var(&profiles, "profile", "resolver profile to compare against the baseline (repeatable)")
	authoritative := fs.Bool("authoritative", false, "compare recursive resolvers against the authoritative nameservers")
	watch := fs.Bool("watch", false, "rerun the check until interrupted")
	interval := fs.Duration("interval", 5*time.Second, "watch interval")
	timeout := fs.Duration("timeout", 0, "maximum watch duration (0 = unlimited)")
	maxIterations := fs.Int("max-iterations", 0, "maximum watch iterations (0 = unlimited)")
	untilOK := fs.Bool("until-ok", false, "in watch mode, stop automatically once the check is healthy")
	_ = fs.Parse(args)
	if len(fs.Args()) != 2 {
		fatal("usage: dnsops compare <name> <type> [--baseline ip:53] [--profile eu] [--profile us] [--resolvers ip:53,ip:53] [--authoritative] [--json|--yaml] [--watch] [--interval 5s] [--timeout 1m] [--max-iterations 60] [--until-ok]")
	}
	name, rrType := fs.Arg(0), fs.Arg(1)
	watchCfg, err := normalizeWatchConfig(*watch, *untilOK, *interval, *timeout, *maxIterations)
	if err != nil {
		fatal(err.Error())
	}
	format, err := resolveOutputFormat(*jsonOut, *yamlOut)
	if err != nil {
		fatal(err.Error())
	}
	resolvers := propagation.DefaultResolvers
	cfg := currentConfig()
	if strings.TrimSpace(*resolverList) != "" {
		resolvers = splitCSV(*resolverList)
	} else if len(profiles) > 0 {
		resolvers, err = propagation.ResolversForProfilesWithCustom(profiles, cfg.Profiles)
		if err != nil {
			fatal(err.Error())
		}
	} else if len(cfg.CompareProfiles) > 0 {
		resolvers, err = propagation.ResolversForProfilesWithCustom(cfg.CompareProfiles, cfg.Profiles)
		if err != nil {
			fatal(err.Error())
		}
	}

	if *authoritative {
		runOnce := func() (authority.Report, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return authority.Run(ctx, *baseline, resolvers, name, rrType)
		}
		if watchCfg.Enabled {
			err := watchLoopFormat(watchCfg, fmt.Sprintf("compare %s %s --authoritative", name, strings.ToUpper(rrType)), format, func() (watchIteration, error) {
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
			handleWatchError(err)
			return
		}
		report, err := runOnce()
		if err != nil {
			fatal(err.Error())
		}
		switch format {
		case outputJSON:
			printJSON(report)
			if !authoritativeHealthy(report) {
				exitCode(1)
			}
			return
		case outputYAML:
			printYAML(report)
			if !authoritativeHealthy(report) {
				exitCode(1)
			}
			return
		}
		renderAuthoritativeCompare(report, *baseline)
		if !authoritativeHealthy(report) {
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
		err := watchLoopFormat(watchCfg, fmt.Sprintf("compare %s %s", name, strings.ToUpper(rrType)), format, func() (watchIteration, error) {
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
		handleWatchError(err)
		return
	}
	report, err := runOnce()
	if err != nil {
		fatal(err.Error())
	}
	switch format {
	case outputJSON:
		printJSON(report)
		if !compareHealthy(report) {
			exitCode(1)
		}
		return
	case outputYAML:
		printYAML(report)
		if !compareHealthy(report) {
			exitCode(1)
		}
		return
	}
	renderCompare(report)
	if !compareHealthy(report) {
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
	authRows := make([][]string, 0, len(report.Authoritative))
	for _, r := range report.Authoritative {
		status := "ok"
		detail := strings.Join(r.Values, ", ")
		if r.Error != "" {
			status = "error"
			detail = "(error: " + r.Error + ")"
		} else if !r.Matches {
			status = "diff"
			detail = "(diff: " + detail + ")"
		}
		authRows = append(authRows, []string{r.Nameserver, detail, statusColor(status)})
	}
	renderTable([]string{"nameserver", "answer", "status"}, authRows)
	fmt.Println("\nrecursive resolvers:")
	recRows := make([][]string, 0, len(report.Resolvers))
	for _, r := range report.Resolvers {
		status := "ok"
		detail := strings.Join(r.Values, ", ")
		if r.Error != "" {
			status = "error"
			detail = "(error: " + r.Error + ")"
		} else if !r.Matches {
			status = "diff"
			detail = "(diff: " + detail + ")"
		}
		recRows = append(recRows, []string{r.Resolver, detail, statusColor(status)})
	}
	renderTable([]string{"resolver", "answer", "status"}, recRows)
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
	rows := make([][]string, 0, len(report.Resolvers))
	for _, r := range report.Resolvers {
		status := "ok"
		detail := strings.Join(r.Values, ", ")
		if r.Error != "" {
			status = "error"
			detail = "(error: " + r.Error + ")"
		} else if !r.Matches {
			status = "diff"
			detail = "(diff: " + detail + ")"
		}
		rows = append(rows, []string{r.Resolver, detail, statusColor(status)})
	}
	renderTable([]string{"resolver", "answer", "status"}, rows)
	fmt.Printf("\nsummary: %d/%d match the baseline\n", report.Healthy, report.Total)
}
