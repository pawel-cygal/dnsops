package propagation

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"dnsops/internal/dnsquery"
)

var DefaultResolvers = []string{
	"1.1.1.1:53",
	"8.8.8.8:53",
	"9.9.9.9:53",
	"208.67.222.222:53",
}

var regionalProfiles = map[string][]string{
	"default": DefaultResolvers,
	"eu": {
		"9.9.9.9:53",
		"149.112.112.112:53",
		"94.140.14.14:53",
		"94.140.15.15:53",
		"1.1.1.1:53",
		"8.8.8.8:53",
	},
	"us": {
		"1.1.1.1:53",
		"1.0.0.1:53",
		"8.8.8.8:53",
		"8.8.4.4:53",
		"208.67.222.222:53",
		"208.67.220.220:53",
	},
	"asia": {
		"1.1.1.1:53",
		"1.0.0.1:53",
		"8.8.8.8:53",
		"8.8.4.4:53",
		"9.9.9.9:53",
		"94.140.14.14:53",
	},
	"oceania": {
		"1.1.1.1:53",
		"1.0.0.1:53",
		"8.8.8.8:53",
		"208.67.222.222:53",
		"9.9.9.9:53",
	},
	"south-america": {
		"1.1.1.1:53",
		"8.8.8.8:53",
		"9.9.9.9:53",
		"208.67.222.222:53",
		"94.140.14.14:53",
	},
}

var globalProfileOrder = []string{"default", "eu", "us", "asia", "oceania", "south-america"}

type ResolverResult struct {
	Resolver string   `json:"resolver" yaml:"resolver"`
	Values   []string `json:"values,omitempty" yaml:"values,omitempty"`
	Error    string   `json:"error,omitempty" yaml:"error,omitempty"`
	Matches  bool     `json:"matches" yaml:"matches"`
}

type Report struct {
	Name        string           `json:"name" yaml:"name"`
	Type        string           `json:"type" yaml:"type"`
	Expected    []string         `json:"expected" yaml:"expected"`
	HasMajority bool             `json:"has_majority" yaml:"has_majority"`
	Resolvers   []ResolverResult `json:"resolvers" yaml:"resolvers"`
	Healthy     int              `json:"healthy" yaml:"healthy"`
	Total       int              `json:"total" yaml:"total"`
}

func Run(ctx context.Context, resolvers []string, name, rrType string) Report {
	if len(resolvers) == 0 {
		resolvers = DefaultResolvers
	}
	out := make([]ResolverResult, len(resolvers))
	var wg sync.WaitGroup
	for i, resolver := range resolvers {
		wg.Add(1)
		go func(i int, resolver string) {
			defer wg.Done()
			res, err := dnsquery.Query(ctx, resolver, name, rrType)
			if err != nil {
				out[i] = ResolverResult{Resolver: resolver, Error: err.Error()}
				return
			}
			out[i] = ResolverResult{Resolver: resolver, Values: res.Values}
		}(i, resolver)
	}
	wg.Wait()

	expected, hasMajority := majorityValues(out)
	healthy := 0
	for i := range out {
		if hasMajority && out[i].Error == "" && slices.Equal(out[i].Values, expected) {
			out[i].Matches = true
			healthy++
		}
	}
	return Report{
		Name:        name,
		Type:        rrType,
		Expected:    expected,
		HasMajority: hasMajority,
		Resolvers:   out,
		Healthy:     healthy,
		Total:       len(out),
	}
}

func majorityValues(results []ResolverResult) ([]string, bool) {
	type bucket struct {
		values []string
		count  int
	}
	var buckets []bucket
	successes := 0
	for _, r := range results {
		if r.Error != "" {
			continue
		}
		successes++
		found := false
		for i := range buckets {
			if slices.Equal(buckets[i].values, r.Values) {
				buckets[i].count++
				found = true
				break
			}
		}
		if !found {
			copied := append([]string(nil), r.Values...)
			buckets = append(buckets, bucket{values: copied, count: 1})
		}
	}
	if len(buckets) == 0 {
		return nil, false
	}
	best := buckets[0]
	for _, b := range buckets[1:] {
		if b.count > best.count {
			best = b
		}
	}
	return best.values, best.count > successes/2
}

func FirstError(report Report) error {
	for _, r := range report.Resolvers {
		if r.Error != "" {
			return errors.New(r.Error)
		}
	}
	return nil
}

func AvailableProfiles() []string {
	out := append([]string(nil), globalProfileOrder...)
	out = append(out, "global")
	sort.Strings(out)
	return out
}

func ResolversForProfiles(profiles []string) ([]string, error) {
	if len(profiles) == 0 {
		return append([]string(nil), DefaultResolvers...), nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(list []string) {
		for _, resolver := range list {
			resolver = dnsquery.NormalizeResolver(resolver)
			if !seen[resolver] {
				seen[resolver] = true
				out = append(out, resolver)
			}
		}
	}
	for _, profile := range profiles {
		profile = normalizeProfile(profile)
		if profile == "global" {
			for _, name := range globalProfileOrder {
				add(regionalProfiles[name])
			}
			continue
		}
		list, ok := regionalProfiles[profile]
		if !ok {
			return nil, fmt.Errorf("unknown resolver profile %q (available: %s)", profile, strings.Join(AvailableProfiles(), ", "))
		}
		add(list)
	}
	return out, nil
}

func normalizeProfile(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	name = strings.ReplaceAll(name, "_", "-")
	return strings.ReplaceAll(name, " ", "-")
}
