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
	args = normalizeFlagArgs(args, map[string]bool{"--resolver": true})
	fs := flag.NewFlagSet("reverse", flag.ExitOnError)
	resolver := fs.String("resolver", "1.1.1.1:53", "DNS resolver to query")
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	_ = fs.Parse(args)
	if len(fs.Args()) != 1 {
		fatal("usage: dnsops reverse <ip> [--resolver IP:PORT] [--json|--yaml]")
	}
	format, err := resolveOutputFormat(*jsonOut, *yamlOut)
	if err != nil {
		fatal(err.Error())
	}
	ip := fs.Arg(0)
	ptrName, err := reverseName(ip)
	if err != nil {
		fatal(err.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	records, err := rawdns.Query(ctx, *resolver, ptrName, "PTR")
	if err != nil {
		fatal(err.Error())
	}
	report := struct {
		IP       string          `json:"ip" yaml:"ip"`
		Name     string          `json:"name" yaml:"name"`
		Resolver string          `json:"resolver" yaml:"resolver"`
		Answers  []rawdns.Record `json:"answers" yaml:"answers"`
	}{
		IP:       ip,
		Name:     ptrName,
		Resolver: dnsquery.NormalizeResolver(*resolver),
		Answers:  records,
	}
	switch format {
	case outputJSON:
		printJSON(report)
	case outputYAML:
		printYAML(report)
	default:
		fmt.Printf("%s  PTR\n", report.IP)
		fmt.Printf("name: %s\n", report.Name)
		fmt.Printf("resolver: %s\n\n", report.Resolver)
		if len(report.Answers) == 0 {
			fmt.Println("(no PTR answers)")
			return
		}
		rows := make([][]string, 0, len(report.Answers))
		for _, rec := range report.Answers {
			rows = append(rows, []string{fmt.Sprintf("%d", rec.TTL), rec.Data})
		}
		renderTable([]string{"ttl", "ptr"}, rows)
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
