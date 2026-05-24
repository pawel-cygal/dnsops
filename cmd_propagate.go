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
	args = normalizeFlagArgs(args, map[string]bool{"--resolvers": true, "--interval": true})
	fs := flag.NewFlagSet("propagate", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	resolverList := fs.String("resolvers", "", "comma-separated resolver list (default: built-in public resolvers)")
	watch := fs.Bool("watch", false, "rerun the check until interrupted")
	interval := fs.Duration("interval", 5*time.Second, "watch interval")
	untilOK := fs.Bool("until-ok", false, "in watch mode, stop automatically once the check is healthy")
	_ = fs.Parse(args)
	if len(fs.Args()) != 2 {
		fatal("usage: dnsops propagate <name> <type> [--json] [--resolvers ip:53,ip:53] [--watch] [--interval 5s] [--until-ok]")
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
	runOnce := func() (propagation.Report, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return propagation.Run(ctx, resolvers, name, rrType), nil
	}
	if watchCfg.Enabled {
		err := watchLoop(watchCfg, fmt.Sprintf("propagate %s %s", name, strings.ToUpper(rrType)), *jsonOut, func() (watchIteration, error) {
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

	renderPropagate(report)
	if report.Healthy != report.Total {
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
		fmt.Println("no majority answer")
		fmt.Println()
	}
	fmt.Println("resolvers:")
	for _, r := range report.Resolvers {
		status := "ok"
		detail := strings.Join(r.Values, ", ")
		if r.Error != "" {
			status = "error"
			detail = r.Error
		} else if !r.Matches {
			status = "drift"
		}
		fmt.Printf("  %-16s  %-6s  %s\n", r.Resolver, status, detail)
	}
	if report.HasMajority {
		fmt.Printf("\nsummary: %d/%d match the majority answer\n", report.Healthy, report.Total)
	} else {
		fmt.Printf("\nsummary: no majority answer across %d resolver(s)\n", report.Total)
	}
}
