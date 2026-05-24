package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"dnsops/internal/dnsquery"
	"dnsops/internal/rawdns"
)

func cmdLookup(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"--resolver": true, "--interval": true, "--timeout": true, "--max-iterations": true})
	fs := flag.NewFlagSet("lookup", flag.ExitOnError)
	resolver := fs.String("resolver", defaultResolver(), "DNS resolver to query")
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	ttlOut := fs.Bool("ttl", false, "show TTL-aware answers via raw DNS queries")
	watch := fs.Bool("watch", false, "rerun the lookup until interrupted")
	interval := fs.Duration("interval", 5*time.Second, "watch interval")
	timeout := fs.Duration("timeout", 0, "maximum watch duration (0 = unlimited)")
	maxIterations := fs.Int("max-iterations", 0, "maximum watch iterations (0 = unlimited)")
	_ = fs.Parse(args)
	if len(fs.Args()) != 2 {
		fatal("usage: dnsops lookup <name> <type> [--resolver IP:PORT] [--json|--yaml] [--ttl] [--watch] [--interval 5s] [--timeout 1m] [--max-iterations 60]")
	}
	name, rrType := fs.Arg(0), fs.Arg(1)
	format, err := resolveOutputFormat(*jsonOut, *yamlOut)
	if err != nil {
		fatal(err.Error())
	}
	watchCfg, err := normalizeWatchConfig(*watch, false, *interval, *timeout, *maxIterations)
	if err != nil {
		fatal(err.Error())
	}

	if *ttlOut {
		runOnce := func() (any, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			records, err := rawdns.Query(ctx, *resolver, name, rrType)
			if err != nil {
				return nil, err
			}
			return struct {
				Name     string          `json:"name" yaml:"name"`
				Type     string          `json:"type" yaml:"type"`
				Resolver string          `json:"resolver" yaml:"resolver"`
				Answers  []rawdns.Record `json:"answers" yaml:"answers"`
			}{
				Name:     name,
				Type:     rrType,
				Resolver: rawdnsResolver(*resolver),
				Answers:  records,
			}, nil
		}
		render := func(payload any) {
			report := payload.(struct {
				Name     string          `json:"name" yaml:"name"`
				Type     string          `json:"type" yaml:"type"`
				Resolver string          `json:"resolver" yaml:"resolver"`
				Answers  []rawdns.Record `json:"answers" yaml:"answers"`
			})
			fmt.Printf("%s  %s\n", report.Name, report.Type)
			fmt.Printf("resolver: %s\n\n", report.Resolver)
			rows := make([][]string, 0, len(report.Answers))
			for _, rec := range report.Answers {
				rows = append(rows, []string{fmt.Sprintf("%d", rec.TTL), rec.Type, rec.Data})
			}
			renderTable([]string{"ttl", "type", "answer"}, rows)
		}
		if watchCfg.Enabled {
			err := watchLoopFormat(watchCfg, fmt.Sprintf("lookup %s %s --ttl", name, rrType), format, func() (watchIteration, error) {
				payload, err := runOnce()
				if err != nil {
					return watchIteration{}, err
				}
				return watchIteration{
					Result:  payload,
					Healthy: false,
					Render: func() {
						render(payload)
					},
				}, nil
			})
			handleWatchError(err)
			return
		}
		payload, err := runOnce()
		if err != nil {
			fatal(err.Error())
		}
		switch format {
		case outputJSON:
			printJSON(payload)
		case outputYAML:
			printYAML(payload)
		default:
			render(payload)
		}
		return
	}

	runOnce := func() (dnsquery.Result, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		return dnsquery.Query(ctx, *resolver, name, rrType)
	}
	render := func(res dnsquery.Result) {
		fmt.Printf("%s  %s\n", res.Name, res.Type)
		fmt.Printf("resolver: %s\n", res.Resolver)
		if len(res.Values) == 0 {
			fmt.Println("(no answers)")
			return
		}
		fmt.Println()
		for _, v := range res.Values {
			fmt.Printf("  %s\n", v)
		}
	}
	if watchCfg.Enabled {
		err := watchLoopFormat(watchCfg, fmt.Sprintf("lookup %s %s", name, rrType), format, func() (watchIteration, error) {
			report, err := runOnce()
			if err != nil {
				return watchIteration{}, err
			}
			return watchIteration{
				Result:  report,
				Healthy: false,
				Render: func() {
					render(report)
				},
			}, nil
		})
		handleWatchError(err)
		return
	}
	res, err := runOnce()
	if err != nil {
		fatal(err.Error())
	}
	switch format {
	case outputJSON:
		printJSON(res)
	case outputYAML:
		printYAML(res)
	default:
		render(res)
	}
}

func rawdnsResolver(addr string) string {
	return dnsquery.NormalizeResolver(addr)
}
