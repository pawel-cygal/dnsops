package delegation

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"dnsops/internal/rawdns"
)

type NSCheck struct {
	Nameserver string            `json:"nameserver"`
	NS         []string          `json:"ns,omitempty"`
	SOA        *rawdns.SOAResult `json:"soa,omitempty"`
	Error      string            `json:"error,omitempty"`
}

type Report struct {
	Zone                string    `json:"zone"`
	DiscoveryResolver   string    `json:"discovery_resolver"`
	ParentZone          string    `json:"parent_zone,omitempty"`
	ParentNS            []string  `json:"parent_ns,omitempty"`
	ParentChecks        []NSCheck `json:"parent_checks,omitempty"`
	ParentDelegation    []string  `json:"parent_delegation,omitempty"`
	ChildApexNS         []string  `json:"child_apex_ns,omitempty"`
	ChildChecks         []NSCheck `json:"child_checks,omitempty"`
	ParentMatchesChild  bool      `json:"parent_matches_child"`
	ChildNSConsistent   bool      `json:"child_ns_consistent"`
	SOASerialConsistent bool      `json:"soa_serial_consistent"`
}

func Run(ctx context.Context, discoveryResolver, zone string) (Report, error) {
	zone = strings.TrimSuffix(strings.TrimSpace(zone), ".")
	if zone == "" {
		return Report{}, fmt.Errorf("zone is required")
	}
	parentZone, err := parentZone(zone)
	if err != nil {
		return Report{}, err
	}
	parentApexNS, err := rawdns.Query(ctx, discoveryResolver, parentZone, "NS")
	if err != nil {
		return Report{}, err
	}
	parentResolvers := recordData(parentApexNS)
	report := Report{
		Zone:              zone,
		DiscoveryResolver: discoveryResolver,
		ParentZone:        parentZone,
		ParentNS:          parentResolvers,
	}
	for _, ns := range parentResolvers {
		check := NSCheck{Nameserver: ns}
		nsRecords, err := rawdns.Query(ctx, ns, zone, "NS")
		if err != nil {
			check.Error = err.Error()
			report.ParentChecks = append(report.ParentChecks, check)
			continue
		}
		check.NS = recordData(nsRecords)
		if len(report.ParentDelegation) == 0 && len(check.NS) > 0 {
			report.ParentDelegation = append([]string(nil), check.NS...)
		}
		report.ParentChecks = append(report.ParentChecks, check)
	}
	for _, ns := range report.ParentDelegation {
		check := NSCheck{Nameserver: ns}
		nsRecords, err := rawdns.Query(ctx, ns, zone, "NS")
		if err != nil {
			check.Error = err.Error()
			report.ChildChecks = append(report.ChildChecks, check)
			continue
		}
		check.NS = recordData(nsRecords)
		soa, err := rawdns.LookupSOA(ctx, ns, zone)
		if err != nil {
			check.Error = err.Error()
		} else {
			check.SOA = &soa
		}
		report.ChildChecks = append(report.ChildChecks, check)
	}
	report.ChildApexNS = majorityNS(report.ChildChecks)
	report.ChildNSConsistent = childNSConsistent(report.ChildChecks)
	report.ParentMatchesChild =
		stringSlicesEqual(sortedCopy(report.ParentDelegation), sortedCopy(report.ChildApexNS))
	report.SOASerialConsistent = soaSerialConsistent(report.ChildChecks)
	return report, nil
}

func parentZone(zone string) (string, error) {
	parts := strings.Split(zone, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("zone %q has no parent zone", zone)
	}
	return strings.Join(parts[1:], "."), nil
}

func recordData(in []rawdns.Record) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		out = append(out, r.Data)
	}
	return out
}

func soaSerialConsistent(checks []NSCheck) bool {
	var serial uint32
	seen := false
	for _, c := range checks {
		if c.SOA == nil {
			continue
		}
		if !seen {
			serial = c.SOA.Serial
			seen = true
			continue
		}
		if c.SOA.Serial != serial {
			return false
		}
	}
	return seen
}

func childNSConsistent(checks []NSCheck) bool {
	var baseline []string
	seen := false
	for _, c := range checks {
		if len(c.NS) == 0 {
			continue
		}
		current := sortedCopy(c.NS)
		if !seen {
			baseline = current
			seen = true
			continue
		}
		if !stringSlicesEqual(baseline, current) {
			return false
		}
	}
	return seen
}

func majorityNS(checks []NSCheck) []string {
	type bucket struct {
		values []string
		count  int
	}
	var buckets []bucket
	for _, c := range checks {
		if len(c.NS) == 0 {
			continue
		}
		current := sortedCopy(c.NS)
		found := false
		for i := range buckets {
			if stringSlicesEqual(buckets[i].values, current) {
				buckets[i].count++
				found = true
				break
			}
		}
		if !found {
			buckets = append(buckets, bucket{values: current, count: 1})
		}
	}
	if len(buckets) == 0 {
		return nil
	}
	best := buckets[0]
	for _, b := range buckets[1:] {
		if b.count > best.count {
			best = b
		}
	}
	return append([]string(nil), best.values...)
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
