package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"dnsops/internal/propagation"
)

func cmdPropagate(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"--resolvers": true, "--profile": true, "--interval": true, "--timeout": true, "--max-iterations": true})
	fs := flag.NewFlagSet("propagate", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	resolverList := fs.String("resolvers", "", "comma-separated resolver list (default: built-in public resolvers)")
	var profiles multiString
	fs.Var(&profiles, "profile", "resolver profile to use (repeatable: default, global, eu, us, asia, oceania, south-america)")
	watch := fs.Bool("watch", false, "rerun the check until interrupted")
	interval := fs.Duration("interval", 5*time.Second, "watch interval")
	timeout := fs.Duration("timeout", 0, "maximum watch duration (0 = unlimited)")
	maxIterations := fs.Int("max-iterations", 0, "maximum watch iterations (0 = unlimited)")
	untilOK := fs.Bool("until-ok", false, "in watch mode, stop automatically once the check is healthy")
	_ = fs.Parse(args)
	if len(fs.Args()) != 2 {
		fatal("usage: dnsops propagate <name> <type> [--json|--yaml] [--profile eu] [--profile us] [--resolvers ip:53,ip:53] [--watch] [--interval 5s] [--timeout 1m] [--max-iterations 60] [--until-ok]")
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
	if strings.TrimSpace(*resolverList) != "" {
		resolvers = splitCSV(*resolverList)
	} else if len(profiles) > 0 {
		resolvers, err = propagation.ResolversForProfiles(profiles)
		if err != nil {
			fatal(err.Error())
		}
	}
	runOnce := func() (propagation.Report, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return propagation.Run(ctx, resolvers, name, rrType), nil
	}
	if watchCfg.Enabled {
		err := watchLoopFormat(watchCfg, fmt.Sprintf("propagate %s %s", name, strings.ToUpper(rrType)), format, func() (watchIteration, error) {
			report, err := runOnce()
			if err != nil {
				return watchIteration{}, err
			}
			return watchIteration{
				Result:  report,
				Healthy: propagateHealthy(report),
				Render: func() {
					renderPropagate(report)
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
		if !propagateHealthy(report) {
			exitCode(1)
		}
		return
	case outputYAML:
		printYAML(report)
		if !propagateHealthy(report) {
			exitCode(1)
		}
		return
	}

	renderPropagate(report)
	if !propagateHealthy(report) {
		exitCode(1)
	}
}

func renderPropagate(report propagation.Report) {
	fmt.Printf("%s  %s\n\n", report.Name, strings.ToUpper(report.Type))
	if report.HasMajority && len(report.Expected) > 0 {
		fmt.Println("majority answer:")
		for _, v := range report.Expected {
			fmt.Printf("  %s\n", v)
		}
		fmt.Println()
	} else {
		fmt.Println(statusColor("split") + "  no majority answer")
		fmt.Println()
	}
	rows := make([][]string, 0, len(report.Resolvers))
	for _, r := range report.Resolvers {
		status := "ok"
		detail := strings.Join(r.Values, ", ")
		if r.Error != "" {
			status = "error"
			detail = "(error: " + r.Error + ")"
		} else if report.HasMajority && !r.Matches {
			status = "stale"
			detail = "(stale: " + detail + ")"
		} else if !report.HasMajority {
			status = "split"
			detail = "(split: " + detail + ")"
		}
		rows = append(rows, []string{r.Resolver, detail, statusColor(status)})
	}
	renderTable([]string{"resolver", "answer", "status"}, rows)
	if report.HasMajority {
		fmt.Printf("\nsummary: %d/%d match the majority answer\n", report.Healthy, report.Total)
	} else {
		fmt.Printf("\nsummary: no majority answer across %d resolver(s)\n", report.Total)
	}
}
