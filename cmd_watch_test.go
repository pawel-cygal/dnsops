package main

import (
	"testing"
	"time"

	"dnsops/internal/authority"
	"dnsops/internal/compare"
	"dnsops/internal/propagation"
	"dnsops/internal/verify"
)

func TestNormalizeWatchConfig(t *testing.T) {
	cfg, err := normalizeWatchConfig(false, true, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled || !cfg.UntilOK || cfg.Interval != 5*time.Second {
		t.Fatalf("normalizeWatchConfig() = %+v", cfg)
	}
	if _, err := normalizeWatchConfig(true, false, 0); err == nil {
		t.Fatal("expected invalid interval error")
	}
}

func TestHealthyPredicates(t *testing.T) {
	if !propagateHealthy(propagation.Report{HasMajority: true, Healthy: 4, Total: 4}) {
		t.Fatal("propagateHealthy should require majority and all healthy")
	}
	if propagateHealthy(propagation.Report{HasMajority: false, Healthy: 4, Total: 4}) {
		t.Fatal("propagateHealthy should fail without majority")
	}
	if !compareHealthy(compare.Report{Healthy: 2, Total: 2}) {
		t.Fatal("compareHealthy should pass when all match")
	}
	if !authoritativeHealthy(authority.Report{AuthConsistent: true, HealthyAuth: 2, TotalAuth: 2, HealthyRec: 3, TotalRec: 3}) {
		t.Fatal("authoritativeHealthy should require consistent/auth+rec healthy")
	}
	if authoritativeHealthy(authority.Report{AuthConsistent: false, HealthyAuth: 2, TotalAuth: 2, HealthyRec: 3, TotalRec: 3}) {
		t.Fatal("authoritativeHealthy should fail on inconsistent auth set")
	}
	if !verifyHealthy(verify.Report{Errors: 0}) {
		t.Fatal("verifyHealthy should pass with zero errors")
	}
	if verifyHealthy(verify.Report{Errors: 1}) {
		t.Fatal("verifyHealthy should fail with errors")
	}
}
