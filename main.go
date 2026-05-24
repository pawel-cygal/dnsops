package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "lookup":
		cmdLookup(os.Args[2:])
	case "reverse":
		cmdReverse(os.Args[2:])
	case "caa":
		cmdCAA(os.Args[2:])
	case "soa":
		cmdSOA(os.Args[2:])
	case "delegations":
		cmdDelegations(os.Args[2:])
	case "propagate":
		cmdPropagate(os.Args[2:])
	case "compare":
		cmdCompare(os.Args[2:])
	case "mail":
		cmdMail(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	case "expiry":
		cmdExpiry(os.Args[2:])
	case "dnssec":
		cmdDNSSEC(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fatal("unknown command: " + os.Args[1])
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `dnsops - DNS operations CLI

Usage:
  dnsops lookup <name> <type> [--resolver IP:PORT] [--json|--yaml] [--ttl] [--watch] [--interval 5s] [--timeout 1m] [--max-iterations 60]
  dnsops reverse <ip> [ip...] [--resolver IP:PORT] [--input path] [--json|--yaml]
  dnsops caa <domain> [domain...] [--resolver IP:PORT] [--input path] [--json|--yaml]
  dnsops soa <zone> [--resolver IP:PORT] [--json]
  dnsops delegations <zone> [--resolver IP:PORT] [--json]
  dnsops propagate <name> <type> [--profile global] [--profile eu] [--resolvers ip:53,ip:53] [--json|--yaml] [--watch] [--interval 5s] [--timeout 1m] [--max-iterations 60] [--until-ok]
  dnsops compare <name> <type> [--baseline ip:53] [--profile global] [--profile eu] [--resolvers ip:53,ip:53] [--authoritative] [--json|--yaml] [--watch] [--interval 5s] [--timeout 1m] [--max-iterations 60] [--until-ok]
  dnsops mail <domain> [domain...] [--resolver IP:PORT] [--selector default] [--input path] [--json|--yaml|--prom]
  dnsops verify -f dns.yaml [--resolver IP:PORT] [--json|--yaml|--prom] [--watch] [--interval 5s] [--timeout 1m] [--max-iterations 60] [--until-ok]
  dnsops expiry <domain> [domain...] [--input path] [--warn-days 60] [--critical-days 14] [--json|--yaml|--prom]
  dnsops dnssec <domain> [domain...] [--resolver IP:PORT] [--input path] [--json|--yaml|--prom]

`)
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "dnsops:", msg)
	os.Exit(2)
}
