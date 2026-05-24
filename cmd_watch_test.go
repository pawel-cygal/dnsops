package main

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"dnsops/internal/authority"
	"dnsops/internal/compare"
	"dnsops/internal/propagation"
	"dnsops/internal/verify"
)

func TestNormalizeWatchConfig(t *testing.T) {
	cfg, err := normalizeWatchConfig(false, true, 5*time.Second, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled || !cfg.UntilOK || cfg.Interval != 5*time.Second || cfg.Timeout != 0 || cfg.MaxIterations != 0 {
		t.Fatalf("normalizeWatchConfig() = %+v", cfg)
	}
	if _, err := normalizeWatchConfig(true, false, 0, 0, 0); err == nil {
		t.Fatal("expected invalid interval error")
	}
	if _, err := normalizeWatchConfig(true, false, time.Second, -time.Second, 0); err == nil {
		t.Fatal("expected invalid timeout error")
	}
	if _, err := normalizeWatchConfig(true, false, time.Second, 0, -1); err == nil {
		t.Fatal("expected invalid max-iterations error")
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

func TestWatchLoopFormatContinuesAfterTransientError(t *testing.T) {
	cfg := watchConfig{Enabled: true, Interval: time.Millisecond, MaxIterations: 2}
	calls := 0
	err := watchLoopFormat(cfg, "test", outputJSON, func() (watchIteration, error) {
		calls++
		if calls == 1 {
			return watchIteration{}, errors.New("temporary failure")
		}
		return watchIteration{Result: map[string]string{"status": "ok"}, Healthy: false, Render: func() {}}, nil
	})
	var stopErr watchStopError
	if !errors.As(err, &stopErr) {
		t.Fatalf("expected watchStopError, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("watch loop stopped too early, calls=%d", calls)
	}
}

func TestWatchLoopFormatYAMLDoesNotLeaveTrailingSeparator(t *testing.T) {
	cfg := watchConfig{Enabled: true, Interval: time.Millisecond, MaxIterations: 2}
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = oldStdout
	}()

	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(r)
		done <- string(data)
	}()

	_ = watchLoopFormat(cfg, "test", outputYAML, func() (watchIteration, error) {
		return watchIteration{Result: map[string]string{"status": "ok"}, Healthy: false, Render: func() {}}, nil
	})
	_ = w.Close()
	out := <-done

	if strings.HasSuffix(strings.TrimSpace(out), "---") {
		t.Fatalf("yaml watch output ends with trailing document separator:\n%s", out)
	}
	if strings.Count(out, "---") != 1 {
		t.Fatalf("expected exactly one separator between two yaml docs, got %d:\n%s", strings.Count(out, "---"), out)
	}
}
