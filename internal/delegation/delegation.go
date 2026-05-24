package delegation

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"dnsops/internal/dnsquery"
	"dnsops/internal/rawdns"
)

var dnsqueryQuery = dnsquery.Query

type NSCheck struct {
	Nameserver    string              `json:"nameserver"`
	NS            []string            `json:"ns,omitempty"`
	SOA           *rawdns.SOAResult   `json:"soa,omitempty"`
	Glue          []string            `json:"glue,omitempty"`
	GlueByNS      map[string][]string `json:"glue_by_ns,omitempty"`
	GlueExpected  bool                `json:"glue_expected,omitempty"`
	GlueMissing   bool                `json:"glue_missing,omitempty"`
	PossibleLame  bool                `json:"possible_lame,omitempty"`
	AddressErrors []string            `json:"address_errors,omitempty"`
	LameReasons   []string            `json:"lame_reasons,omitempty"`
	Error         string              `json:"error,omitempty"`
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
	GlueConsistent      bool      `json:"glue_consistent"`
	PossibleLame        bool      `json:"possible_lame"`
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
		delegation, err := rawdns.LookupDelegation(ctx, ns, zone)
		if err != nil {
			check.Error = err.Error()
			report.ParentChecks = append(report.ParentChecks, check)
			continue
		}
		check.NS = delegation.NS
		check.GlueByNS = delegation.Glue
		for _, delegatedNS := range check.NS {
			check.Glue = append(check.Glue, delegation.Glue[strings.ToLower(delegatedNS)]...)
		}
		check.Glue = sortedUnique(check.Glue)
		if len(report.ParentDelegation) == 0 && len(check.NS) > 0 {
			report.ParentDelegation = append([]string(nil), check.NS...)
		}
		report.ParentChecks = append(report.ParentChecks, check)
	}
	for _, ns := range report.ParentDelegation {
		check := NSCheck{
			Nameserver:   ns,
			GlueExpected: inBailiwick(zone, ns),
		}
		check.Glue = glueFor(report.ParentChecks, ns)
		check.GlueMissing = check.GlueExpected && len(check.Glue) == 0
		check.AddressErrors = nameserverAddressErrors(ctx, discoveryResolver, ns)
		if len(check.AddressErrors) > 0 {
			check.LameReasons = append(check.LameReasons, check.AddressErrors...)
		}
		nsRecords, err := rawdns.Query(ctx, ns, zone, "NS")
		if err != nil {
			check.Error = err.Error()
			check.PossibleLame = true
			check.LameReasons = append(check.LameReasons, "zone NS query failed")
			report.ChildChecks = append(report.ChildChecks, check)
			continue
		}
		check.NS = recordData(nsRecords)
		if len(check.NS) == 0 {
			check.PossibleLame = true
			check.LameReasons = append(check.LameReasons, "zone NS query returned no answers")
		}
		soa, err := rawdns.LookupSOA(ctx, ns, zone)
		if err != nil {
			check.Error = err.Error()
			check.PossibleLame = true
			check.LameReasons = append(check.LameReasons, "SOA query failed")
		} else {
			check.SOA = &soa
		}
		if check.GlueMissing {
			check.LameReasons = append(check.LameReasons, "required parent-side glue is missing")
		}
		if addressReachabilityBroken(check.AddressErrors) {
			check.PossibleLame = true
		}
		report.ChildChecks = append(report.ChildChecks, check)
	}
	report.ChildApexNS = majorityNS(report.ChildChecks)
	report.ChildNSConsistent = childNSConsistent(report.ChildChecks)
	report.ParentMatchesChild =
		stringSlicesEqual(sortedCopy(report.ParentDelegation), sortedCopy(report.ChildApexNS))
	report.SOASerialConsistent = soaSerialConsistent(report.ChildChecks)
	report.GlueConsistent = glueConsistent(report.ChildChecks)
	report.PossibleLame = possibleLame(report.ChildChecks)
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

func glueFor(parentChecks []NSCheck, nameserver string) []string {
	nameserver = strings.TrimSuffix(strings.ToLower(nameserver), ".")
	for _, check := range parentChecks {
		if len(check.NS) == 0 || len(check.Glue) == 0 {
			continue
		}
		for _, delegatedNS := range check.NS {
			if strings.TrimSuffix(strings.ToLower(delegatedNS), ".") == nameserver {
				return append([]string(nil), check.GlueByNS[nameserver]...)
			}
		}
	}
	return nil
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

func inBailiwick(zone, nameserver string) bool {
	zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	nameserver = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(nameserver)), ".")
	return nameserver == zone || strings.HasSuffix(nameserver, "."+zone)
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	j := 1
	for i := 1; i < len(out); i++ {
		if out[i] != out[i-1] {
			out[j] = out[i]
			j++
		}
	}
	return out[:j]
}

func glueConsistent(checks []NSCheck) bool {
	for _, c := range checks {
		if c.GlueMissing {
			return false
		}
	}
	return true
}

func possibleLame(checks []NSCheck) bool {
	for _, c := range checks {
		if c.PossibleLame {
			return true
		}
	}
	return false
}

func nameserverAddressErrors(ctx context.Context, resolver, nameserver string) []string {
	var errs []string
	aRes, aErr := dnsqueryQuery(ctx, resolver, nameserver, "A")
	aaaaRes, aaaaErr := dnsqueryQuery(ctx, resolver, nameserver, "AAAA")
	if aErr != nil {
		errs = append(errs, "A lookup failed: "+aErr.Error())
	}
	if aaaaErr != nil {
		errs = append(errs, "AAAA lookup failed: "+aaaaErr.Error())
	}
	aOK := aErr == nil && len(aRes.Values) > 0
	aaaaOK := aaaaErr == nil && len(aaaaRes.Values) > 0
	if !aOK && !aaaaOK && aErr == nil && aaaaErr == nil {
		errs = append(errs, "no A/AAAA address records found for nameserver")
	}
	return errs
}

func addressReachabilityBroken(errs []string) bool {
	if len(errs) == 0 {
		return false
	}
	for _, err := range errs {
		if strings.Contains(err, "no A/AAAA address records found for nameserver") {
			return true
		}
	}
	aFailed := false
	aaaaFailed := false
	for _, err := range errs {
		if strings.HasPrefix(err, "A lookup failed:") {
			aFailed = true
		}
		if strings.HasPrefix(err, "AAAA lookup failed:") {
			aaaaFailed = true
		}
	}
	return aFailed && aaaaFailed
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
