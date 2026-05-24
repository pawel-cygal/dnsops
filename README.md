# dnsops

`dnsops` is a small DNS operations CLI for DevOps/SRE workflows.

It is intentionally read-only. The goal is to make DNS changes, propagation checks, mail-DNS sanity checks, delegation diagnostics, and domain-expiry checks easier to inspect from a terminal without relying on browser tools.

## Current scope

Implemented commands:
- `lookup`
- `reverse`
- `caa`
- `soa`
- `delegations`
- `propagate`
- `compare`
- `mail`
- `verify`
- `expiry`
- `dnssec`

The current tool is already beyond the original MVP sketch:
- basic record lookups
- reverse PTR lookups
- CAA inspection
- propagation checks across multiple resolvers
- recursive vs authoritative comparison
- mail DNS checks
- expected-state verification from YAML
- SOA and delegation diagnostics
- domain expiry via RDAP
- DNSSEC status checks

## Commands

Examples:

```bash
dnsops lookup app.example.com A
dnsops lookup app.example.com A --ttl
dnsops lookup app.example.com A --ttl --watch --interval 1s
dnsops reverse 203.0.113.10
dnsops caa example.com
dnsops lookup example.com MX --resolver 1.1.1.1:53
dnsops lookup _dmarc.example.com TXT --json

dnsops soa example.com
dnsops delegations example.com

dnsops propagate app.example.com A
dnsops propagate app.example.com A --watch --until-ok
dnsops propagate app.example.com A --until-ok --timeout 2m
dnsops propagate app.example.com A --profile eu --profile us
dnsops compare app.example.com A --baseline 1.1.1.1:53 --resolvers 8.8.8.8:53,9.9.9.9:53
dnsops compare app.example.com A --authoritative
dnsops compare app.example.com A --authoritative --watch --interval 2s

dnsops mail example.com --selector default --selector google
dnsops verify -f dns.yaml
dnsops verify -f dns.yaml --watch
dnsops verify -f dns.yaml --yaml
dnsops expiry example.com example.org
dnsops dnssec example.com
```

Flags may be placed after positional arguments in the examples above; the CLI normalizes them before parsing.

## Command notes

### `lookup`

Current scope:
- supported types: `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`
- optional custom resolver via `--resolver`
- plain text, `--json`, or `--yaml`
- `--ttl` switches to raw DNS answers with TTLs for the same supported record types
- `--watch` and `--interval` work for both normal and TTL-aware lookups

Notes:
- `lookup` deliberately does not expose `SOA`; use `dnsops soa <zone>` for that
- `--ttl` uses raw DNS queries and returns answer records with TTLs
- `lookup --ttl --watch --interval 1s` is the best fit when you want to watch TTLs converge in near real time without manually rerunning the command

### `reverse`

Current scope:
- reverse PTR lookup for IPv4 and IPv6 addresses
- plain text, `--json`, or `--yaml`
- optional custom resolver via `--resolver`

Good fit for:
- validating PTRs during mail / reverse-DNS checks
- checking what a public recursive resolver currently returns for an IP

### `caa`

Current scope:
- fetches `CAA` records for a domain
- plain text, `--json`, or `--yaml`
- optional custom resolver via `--resolver`

Good fit for:
- confirming which CAs are currently authorized
- checking `issue`, `issuewild`, and `iodef` entries before certificate changes

### `soa`

Current scope:
- fetches the SOA record for a zone
- shows:
  - TTL
  - primary NS
  - mailbox
  - serial
  - refresh
  - retry
  - expire
  - min TTL

### `delegations`

Current scope:
- discovers the parent zone
- queries the parent nameservers for the child delegation NS set
- queries the delegated child nameservers for the child apex NS set
- checks whether child nameservers agree with each other
- checks SOA serial consistency across child nameservers
- checks whether in-bailiwick child nameservers appear to have parent-side glue
- emits basic possible-lame hints when delegated nameservers fail zone NS/SOA checks

Semantics:
- `parent delegation` means what the parent zone delegates to the child
- `child apex NS` means the majority child-NS answer at the apex
- the command exits non-zero if:
  - parent delegation and child apex NS differ
  - child nameservers disagree with each other
  - SOA serials disagree
  - required glue appears missing
  - a delegated nameserver looks possibly lame

Limitations:
- parent-zone discovery is still naive and does not use the Public Suffix List
- domains like `example.co.uk` may therefore be diagnosed less precisely than zones under simple suffixes such as `example.com`

### `propagate`

Current scope:
- checks a small built-in resolver set by default
- resolver profiles via repeatable `--profile`
  - `default`
  - `global`
  - `eu`
  - `us`
  - `asia`
  - `oceania`
  - `south-america`
- optional `--resolvers ip:53,ip:53`
- treats the majority answer as the current expected value only when a real majority exists
- supports `--watch`, `--interval`, and `--until-ok`
- supports `--timeout` and `--max-iterations` to stop long-running watches predictably
- supports `--yaml` in addition to `--json`
- exits non-zero if any resolver disagrees or errors

Good fit for:
- waiting on public propagation after a DNS change
- spotting stale caches across public resolvers

Note:
- if resolvers split evenly, the command reports `no majority answer` instead of pretending one side is authoritative
- `--until-ok` implies watch mode
- `--timeout` and `--max-iterations` are useful safety rails for long DNS rollouts
- repeated `--profile` flags are merged, deduplicated, and used as a union
- `global` means the union of all built-in profiles
- `--resolvers` overrides profiles and the default set
- profiles are curated public-resolver buckets, not true multi-region vantage points; from one machine, anycast routing still means you are not literally querying "from Asia" or "from the US"

### `compare`

Current scope:
- baseline resolver via `--baseline`
- compare set via `--resolvers`, repeatable `--profile`, or the built-in public resolver set
- exits non-zero if any resolver differs from the baseline or errors
- `--authoritative` discovers the zone NS set and compares recursive answers against authoritative answers
- supports `--watch`, `--interval`, and `--until-ok`
- supports `--timeout` and `--max-iterations`
- supports `--yaml` in addition to `--json`

Notes:
- `--authoritative` is the preferred mode when you want to answer:
  - "what do authoritative nameservers say?"
  - "which recursive resolvers are still stale?"
- the expected answer is derived from the authoritative set, not blindly from the first successful nameserver response
- zone discovery is still suffix-based and does not use the Public Suffix List, so complex public-suffix cases may require manual judgment
- `--until-ok` implies watch mode
- repeated `--profile` flags are merged and deduplicated
- `global` means the union of all built-in profiles
- `--resolvers` overrides profiles and the default set

### `mail`

Current scope:
- MX presence
- SPF presence + rough DNS-lookup count heuristic
- DMARC presence
- optional DKIM selector presence via repeated `--selector`
- exits non-zero on hard failures; warnings stay informational

Typical use:

```bash
dnsops mail example.com --selector default --selector google
```

### `verify`

Current scope:
- YAML file with `checks:`
- exact `values:` match
- substring-based `contains:` match
- regex-based `regex:` match
- `must_exist` / `must_not_exist`
- `min_ttl` / `max_ttl`
- resolver-based verification with text or JSON output
- optional YAML output via `--yaml`
- supports `--watch`, `--interval`, and `--until-ok`
- supports `--timeout` and `--max-iterations`

Important semantic detail:
- every `contains:` fragment must match within the same returned record
- fragments are not allowed to "spread" across multiple answers
- `--until-ok` implies watch mode

Example `dns.yaml`:

```yaml
zone: example.com

checks:
  - name: app.example.com
    type: A
    values:
      - 1.2.3.4

  - name: _dmarc.example.com
    type: TXT
    contains:
      - v=DMARC1
      - p=reject

  - name: old.example.com
    type: CNAME
    must_not_exist: true

  - name: example.com
    type: MX
    must_exist: true
    min_ttl: 300

  - name: example.com
    type: TXT
    regex: '^v=spf1 .* -all$'
```

### `expiry`

Current scope:
- RDAP lookup through `https://rdap.org/domain/<domain>`
- registrar name when present
- nameservers and status list when present
- expiration date + days remaining
- severity classification:
  - `ok` above `--warn-days`
  - `warn` at/below `--warn-days`
  - `critical` at/below `--critical-days`

Notes:
- text output shows lookup failures directly
- JSON output preserves the failure reason in the `error` field
- RDAP currently goes through `rdap.org`, so gateway-level outages or rate-limits can affect this command even when the domain itself is fine

### `dnssec`

Current scope:
- checks whether the child publishes `DNSKEY`
- checks whether the parent publishes `DS`
- checks whether the `DNSKEY` RRset is signed with `RRSIG`
- classifies the result as:
  - `signed`
  - `unsigned`
  - `broken`

Notes:
- this is a practical DNSSEC status checker, not yet a full chain validator
- parent-zone discovery is still suffix-based and does not use the Public Suffix List
- complex public-suffix cases may therefore require manual judgment

## Output model

The tool currently supports:
- readable terminal output by default
- `--json` on commands where machine-readable output is useful
- `--yaml` on commands where human-readable structured output is useful

Watch mode:
- `propagate`, `compare`, and `verify` support `--watch`
- `lookup` also supports `--watch`, which is especially useful with `--ttl`
- `--interval` controls polling interval (default `5s`)
- `--until-ok` stops automatically once the check becomes healthy
- `--timeout` caps total watch duration
- `--max-iterations` caps total watch iterations
- with `--json --watch`, output is newline-delimited JSON (one object per iteration)
- with `--yaml --watch`, output is newline-delimited YAML documents
- on an interactive terminal, raw watch mode redraws the same screen instead of appending snapshots, so live propagation checks feel closer to a dashboard than a scrolling log

Exit codes are intended to be CI-friendly:
- `0` for healthy / matching / successful checks
- non-zero for mismatches, failed checks, or operational errors

Exact semantics vary slightly by command and may still evolve while the tool is in `v0.x`.

## Implementation notes

The repo intentionally uses two DNS access layers:
- Go stdlib resolver for higher-level read-only checks
- `github.com/miekg/dns` for lower-level queries where TTL, SOA, and delegation details matter

That split keeps the common paths simple while allowing deeper diagnostics where resolver-level control is necessary.

## Non-goals for now

Not implemented yet:
- full DNSSEC chain validation
- deeper delegation analysis beyond the current glue / possible-lame hints
- richer mail checks such as MTA-STS, DANE, or BIMI
- provider API mutation
- zone editing

Those are natural next steps, but the current tool is intentionally read-only and focused on inspection and verification.
