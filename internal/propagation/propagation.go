package propagation

import (
	"context"
	"errors"
	"slices"
	"sync"

	"dnsops/internal/dnsquery"
)

var DefaultResolvers = []string{
	"1.1.1.1:53",
	"8.8.8.8:53",
	"9.9.9.9:53",
	"208.67.222.222:53",
}

type ResolverResult struct {
	Resolver string   `json:"resolver"`
	Values   []string `json:"values,omitempty"`
	Error    string   `json:"error,omitempty"`
	Matches  bool     `json:"matches"`
}

type Report struct {
	Name        string           `json:"name"`
	Type        string           `json:"type"`
	Expected    []string         `json:"expected"`
	HasMajority bool             `json:"has_majority"`
	Resolvers   []ResolverResult `json:"resolvers"`
	Healthy     int              `json:"healthy"`
	Total       int              `json:"total"`
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
			copied := make([]string, len(r.Values))
			copy(copied, r.Values)
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
