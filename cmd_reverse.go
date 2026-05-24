package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"strings"
	"time"

	"dnsops/internal/dnsquery"
	"dnsops/internal/rawdns"

	"github.com/miekg/dns"
)

func cmdReverse(args []string) {
	args = normalizeFlagArgs(args, map[string]bool{"--resolver": true, "--input": true})
	fs := flag.NewFlagSet("reverse", flag.ExitOnError)
	resolver := fs.String("resolver", defaultResolver(), "DNS resolver to query")
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	input := fs.String("input", "", "file with IPs to check, one per line")
	_ = fs.Parse(args)
	if len(fs.Args()) == 0 && *input == "" {
		fatal("usage: dnsops reverse <ip> [ip...] [--resolver IP:PORT] [--input path] [--json|--yaml]")
	}
	format, err := resolveOutputFormat(*jsonOut, *yamlOut)
	if err != nil {
		fatal(err.Error())
	}
	ips, err := mergeTargets(fs.Args(), *input)
	if err != nil {
		fatal(err.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	type report struct {
		IP       string          `json:"ip" yaml:"ip"`
		Name     string          `json:"name,omitempty" yaml:"name,omitempty"`
		Resolver string          `json:"resolver" yaml:"resolver"`
		Answers  []rawdns.Record `json:"answers,omitempty" yaml:"answers,omitempty"`
		Error    string          `json:"error,omitempty" yaml:"error,omitempty"`
	}
	reports := make([]report, 0, len(ips))
	hadErr := false
	for _, ip := range ips {
		rep := report{
			IP:       ip,
			Resolver: dnsquery.NormalizeResolver(*resolver),
		}
		ptrName, err := reverseName(ip)
		if err != nil {
			rep.Error = err.Error()
			hadErr = true
			reports = append(reports, rep)
			continue
		}
		rep.Name = ptrName
		records, err := rawdns.Query(ctx, *resolver, ptrName, "PTR")
		if err != nil {
			rep.Error = err.Error()
			hadErr = true
		} else {
			rep.Answers = records
		}
		reports = append(reports, rep)
	}
	switch format {
	case outputJSON:
		printJSON(reports)
	case outputYAML:
		printYAML(reports)
	default:
		for _, report := range reports {
			fmt.Printf("%s  PTR\n", report.IP)
			if report.Name != "" {
				fmt.Printf("name: %s\n", report.Name)
			}
			fmt.Printf("resolver: %s\n\n", report.Resolver)
			if report.Error != "" {
				fmt.Printf("error: %s\n\n", report.Error)
				continue
			}
			if len(report.Answers) == 0 {
				fmt.Println("(no PTR answers)")
				fmt.Println()
				continue
			}
			rows := make([][]string, 0, len(report.Answers))
			for _, rec := range report.Answers {
				rows = append(rows, []string{fmt.Sprintf("%d", rec.TTL), rec.Data})
			}
			renderTable([]string{"ttl", "ptr"}, rows)
			fmt.Println()
		}
	}
	if hadErr {
		exitCode(1)
	}
}

func reverseName(ip string) (string, error) {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return "", fmt.Errorf("invalid IP %q", ip)
	}
	ptr, err := dns.ReverseAddr(parsed.String())
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(ptr, "."), nil
}
