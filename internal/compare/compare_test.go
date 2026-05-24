package compare

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"dnsops/internal/dnsquery"
)

func TestRun(t *testing.T) {
	ctx := context.Background()
	stub := func(_ context.Context, resolverAddr, name, rrType string) (dnsquery.Result, error) {
		if name != "app.example.com" || rrType != "A" {
			return dnsquery.Result{}, errors.New("unexpected query")
		}
		switch resolverAddr {
		case "1.1.1.1":
			return dnsquery.Result{
				Name:     name,
				Type:     rrType,
				Resolver: dnsquery.NormalizeResolver(resolverAddr),
				Values:   []string{"1.1.1.1"},
			}, nil
		case "8.8.8.8":
			return dnsquery.Result{
				Name:     name,
				Type:     rrType,
				Resolver: dnsquery.NormalizeResolver(resolverAddr),
				Values:   []string{"1.1.1.1"},
			}, nil
		case "9.9.9.9":
			return dnsquery.Result{
				Name:     name,
				Type:     rrType,
				Resolver: dnsquery.NormalizeResolver(resolverAddr),
				Values:   []string{"2.2.2.2"},
			}, nil
		default:
			return dnsquery.Result{}, errors.New("timeout")
		}
	}

	report, err := run(ctx, stub, "1.1.1.1", []string{"8.8.8.8", "9.9.9.9", "208.67.222.222"}, "app.example.com", "A")
	if err != nil {
		t.Fatal(err)
	}
	if report.Baseline != "1.1.1.1:53" {
		t.Fatalf("Baseline = %q, want 1.1.1.1:53", report.Baseline)
	}
	if !reflect.DeepEqual(report.Expected, []string{"1.1.1.1"}) {
		t.Fatalf("Expected = %v, want [1.1.1.1]", report.Expected)
	}
	if report.Healthy != 1 || report.Total != 3 {
		t.Fatalf("Healthy/Total = %d/%d, want 1/3", report.Healthy, report.Total)
	}
	if !report.Resolvers[0].Matches {
		t.Fatal("first resolver should match baseline")
	}
	if report.Resolvers[1].Matches {
		t.Fatal("second resolver should differ from baseline")
	}
	if report.Resolvers[2].Error == "" {
		t.Fatal("third resolver should surface error")
	}
}

func TestRunBaselineError(t *testing.T) {
	ctx := context.Background()
	stub := func(_ context.Context, resolverAddr, name, rrType string) (dnsquery.Result, error) {
		return dnsquery.Result{}, errors.New("boom")
	}
	_, err := run(ctx, stub, "1.1.1.1", []string{"8.8.8.8"}, "app.example.com", "A")
	if err == nil {
		t.Fatal("expected baseline query error")
	}
}
