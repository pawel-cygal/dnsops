package compare

import (
	"context"
	"slices"
	"sync"

	"dnsops/internal/dnsquery"
)

type queryFunc func(ctx context.Context, resolverAddr, name, rrType string) (dnsquery.Result, error)

type ResolverResult struct {
	Resolver string   `json:"resolver"`
	Values   []string `json:"values,omitempty"`
	Error    string   `json:"error,omitempty"`
	Matches  bool     `json:"matches"`
}

type Report struct {
	Name      string           `json:"name"`
	Type      string           `json:"type"`
	Baseline  string           `json:"baseline"`
	Expected  []string         `json:"expected"`
	Resolvers []ResolverResult `json:"resolvers"`
	Healthy   int              `json:"healthy"`
	Total     int              `json:"total"`
}

func Run(ctx context.Context, baseline string, resolvers []string, name, rrType string) (Report, error) {
	return run(ctx, dnsquery.Query, baseline, resolvers, name, rrType)
}

func run(ctx context.Context, query queryFunc, baseline string, resolvers []string, name, rrType string) (Report, error) {
	base, err := query(ctx, baseline, name, rrType)
	if err != nil {
		return Report{}, err
	}
	out := make([]ResolverResult, len(resolvers))
	var wg sync.WaitGroup
	for i, resolver := range resolvers {
		wg.Add(1)
		go func(i int, resolver string) {
			defer wg.Done()
			res, err := query(ctx, resolver, name, rrType)
			if err != nil {
				out[i] = ResolverResult{Resolver: resolver, Error: err.Error()}
				return
			}
			out[i] = ResolverResult{
				Resolver: resolver,
				Values:   res.Values,
				Matches:  slices.Equal(res.Values, base.Values),
			}
		}(i, resolver)
	}
	wg.Wait()

	healthy := 0
	for _, r := range out {
		if r.Matches {
			healthy++
		}
	}
	return Report{
		Name:      name,
		Type:      rrType,
		Baseline:  base.Resolver,
		Expected:  base.Values,
		Resolvers: out,
		Healthy:   healthy,
		Total:     len(out),
	}, nil
}
