package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"dnsops/internal/verify"
)

func cmdVerify(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"-f": true, "--resolver": true, "--interval": true})
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	file := fs.String("f", "", "path to dns spec YAML")
	resolver := fs.String("resolver", "1.1.1.1:53", "DNS resolver to query")
	jsonOut := fs.Bool("json", false, "emit JSON")
	watch := fs.Bool("watch", false, "rerun the check until interrupted")
	interval := fs.Duration("interval", 5*time.Second, "watch interval")
	untilOK := fs.Bool("until-ok", false, "in watch mode, stop automatically once the check is healthy")
	_ = fs.Parse(args)
	if *file == "" {
		fatal("usage: dnsops verify -f dns.yaml [--resolver IP:PORT] [--json] [--watch] [--interval 5s] [--until-ok]")
	}
	watchCfg, err := normalizeWatchConfig(*watch, *untilOK, *interval)
	if err != nil {
		fatal(err.Error())
	}
	spec, err := verify.Load(*file)
	if err != nil {
		fatal(err.Error())
	}
	runOnce := func() (verify.Report, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return verify.Run(ctx, *resolver, *file, spec), nil
	}
	if watchCfg.Enabled {
		err := watchLoop(watchCfg, fmt.Sprintf("verify %s", *file), *jsonOut, func() (watchIteration, error) {
			report, err := runOnce()
			if err != nil {
				return watchIteration{}, err
			}
			return watchIteration{
				Result:  report,
				Healthy: verifyHealthy(report),
				Render: func() {
					renderVerify(report)
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
		if report.Errors > 0 {
			exitCode(1)
		}
		return
	}
	renderVerify(report)
	if report.Errors > 0 {
		exitCode(1)
	}
}

func renderVerify(report verify.Report) {
	fmt.Printf("verify  %s\n", report.File)
	fmt.Printf("resolver: %s\n", report.Resolver)
	if report.Zone != "" {
		fmt.Printf("zone: %s\n", report.Zone)
	}
	fmt.Println()
	for _, r := range report.Results {
		status := "ok"
		if !r.OK {
			status = "fail"
		}
		fmt.Printf("%-28s %-5s %-4s\n", r.Name, r.Type, status)
		if len(r.Expected) > 0 {
			fmt.Printf("  expected: %v\n", r.Expected)
		}
		if len(r.Contains) > 0 {
			fmt.Printf("  contains: %v\n", r.Contains)
		}
		if r.Regex != "" {
			fmt.Printf("  regex:    %s\n", r.Regex)
		}
		if r.MustExist {
			fmt.Printf("  must_exist: true\n")
		}
		if r.MustNotExist {
			fmt.Printf("  must_not_exist: true\n")
		}
		if r.MinTTL > 0 {
			fmt.Printf("  min_ttl:  %d\n", r.MinTTL)
		}
		if r.MaxTTL > 0 {
			fmt.Printf("  max_ttl:  %d\n", r.MaxTTL)
		}
		if len(r.Actual) > 0 {
			fmt.Printf("  actual:   %v\n", r.Actual)
		}
		if len(r.ActualTTLs) > 0 {
			fmt.Printf("  ttl:      %v\n", r.ActualTTLs)
		}
		if r.Error != "" {
			fmt.Printf("  error:    %s\n", r.Error)
		}
	}
	fmt.Printf("\nsummary: %d/%d matched\n", report.Matched, report.Total)
}
