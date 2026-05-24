package authority

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"dnsops/internal/dnsquery"
)

type ResolverResult struct {
	Resolver string   `json:"resolver"`
	Values   []string `json:"values,omitempty"`
	Error    string   `json:"error,omitempty"`
	Matches  bool     `json:"matches"`
}

type AuthorityResult struct {
	Nameserver string   `json:"nameserver"`
	Values     []string `json:"values,omitempty"`
	Error      string   `json:"error,omitempty"`
	Matches    bool     `json:"matches"`
}

type Report struct {
	Name           string            `json:"name"`
	Type           string            `json:"type"`
	Zone           string            `json:"zone"`
	Expected       []string          `json:"expected"`
	AuthConsistent bool              `json:"auth_consistent"`
	Authoritative  []AuthorityResult `json:"authoritative"`
	Resolvers      []ResolverResult  `json:"resolvers"`
	HealthyAuth    int               `json:"healthy_authoritative"`
	TotalAuth      int               `json:"total_authoritative"`
	HealthyRec     int               `json:"healthy_recursive"`
	TotalRec       int               `json:"total_recursive"`
}

func Run(ctx context.Context, discoveryResolver string, resolvers []string, name, rrType string) (Report, error) {
	zone, nss, err := discoverZone(ctx, discoveryResolver, name)
	if err != nil {
		return Report{}, err
	}
	report := Report{
		Name:      name,
		Type:      strings.ToUpper(rrType),
		Zone:      zone,
		Resolvers: make([]ResolverResult, 0, len(resolvers)),
	}
	successfulAuth := make([][]string, 0, len(nss))
	for _, ns := range nss {
		res, err := dnsquery.Query(ctx, ns, name, rrType)
		row := AuthorityResult{Nameserver: dnsquery.NormalizeResolver(ns)}
		if err != nil {
			row.Error = err.Error()
		} else {
			row.Values = res.Values
			successfulAuth = append(successfulAuth, res.Values)
		}
		report.Authoritative = append(report.Authoritative, row)
	}
	report.Expected = majorityValues(successfulAuth)
	report.AuthConsistent = authConsistent(successfulAuth, report.Expected)
	for i := range report.Authoritative {
		if report.Authoritative[i].Error == "" && slices.Equal(report.Authoritative[i].Values, report.Expected) {
			report.Authoritative[i].Matches = true
			report.HealthyAuth++
		}
	}
	report.TotalAuth = len(report.Authoritative)
	for _, resolver := range resolvers {
		res, err := dnsquery.Query(ctx, resolver, name, rrType)
		row := ResolverResult{Resolver: dnsquery.NormalizeResolver(resolver)}
		if err != nil {
			row.Error = err.Error()
		} else {
			row.Values = res.Values
			if slices.Equal(res.Values, report.Expected) {
				row.Matches = true
				report.HealthyRec++
			}
		}
		report.Resolvers = append(report.Resolvers, row)
	}
	report.TotalRec = len(report.Resolvers)
	return report, nil
}

func discoverZone(ctx context.Context, resolver, name string) (string, []string, error) {
	for _, zone := range zoneCandidates(name) {
		res, err := dnsquery.Query(ctx, resolver, zone, "NS")
		if err == nil && len(res.Values) > 0 {
			return zone, res.Values, nil
		}
	}
	return "", nil, fmt.Errorf("could not discover authoritative NS for %s", name)
}

func zoneCandidates(name string) []string {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return nil
	}
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return nil
	}
	out := make([]string, 0, len(parts))
	for i := 0; i < len(parts)-1; i++ {
		out = append(out, strings.Join(parts[i:], "."))
	}
	return out
}

func majorityValues(results [][]string) []string {
	type bucket struct {
		values []string
		count  int
	}
	var buckets []bucket
	for _, values := range results {
		found := false
		for i := range buckets {
			if slices.Equal(buckets[i].values, values) {
				buckets[i].count++
				found = true
				break
			}
		}
		if !found {
			copied := append([]string(nil), values...)
			buckets = append(buckets, bucket{values: copied, count: 1})
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
	return best.values
}

func authConsistent(results [][]string, expected []string) bool {
	if len(results) == 0 {
		return false
	}
	for _, values := range results {
		if !slices.Equal(values, expected) {
			return false
		}
	}
	return true
}
