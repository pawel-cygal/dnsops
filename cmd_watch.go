package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"dnsops/internal/authority"
	"dnsops/internal/compare"
	"dnsops/internal/propagation"
	"dnsops/internal/verify"
)

type watchConfig struct {
	Enabled  bool
	UntilOK  bool
	Interval time.Duration
}

type watchJSONEnvelope struct {
	Timestamp string `json:"timestamp"`
	Iteration int    `json:"iteration"`
	Result    any    `json:"result"`
}

type watchIteration struct {
	Result  any
	Healthy bool
	Render  func()
}

func normalizeWatchConfig(enabled, untilOK bool, interval time.Duration) (watchConfig, error) {
	if untilOK {
		enabled = true
	}
	if !enabled {
		return watchConfig{Enabled: false, UntilOK: untilOK, Interval: interval}, nil
	}
	if interval <= 0 {
		return watchConfig{}, fmt.Errorf("interval must be > 0")
	}
	return watchConfig{Enabled: true, UntilOK: untilOK, Interval: interval}, nil
}

func watchLoop(cfg watchConfig, label string, jsonOut bool, run func() (watchIteration, error)) error {
	for iteration := 1; ; iteration++ {
		step, err := run()
		if err != nil {
			return err
		}
		now := time.Now()
		if jsonOut {
			printJSONLine(watchJSONEnvelope{
				Timestamp: now.UTC().Format(time.RFC3339),
				Iteration: iteration,
				Result:    step.Result,
			})
		} else {
			fmt.Printf("[%s] %s\n\n", now.Format("2006-01-02 15:04:05"), label)
			step.Render()
			fmt.Println()
		}
		if cfg.UntilOK && step.Healthy {
			return nil
		}
		time.Sleep(cfg.Interval)
	}
}

func printJSONLine(v any) {
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(v); err != nil {
		fatal(err.Error())
	}
}

func propagateHealthy(report propagation.Report) bool {
	return report.HasMajority && report.Healthy == report.Total
}

func compareHealthy(report compare.Report) bool {
	return report.Healthy == report.Total
}

func authoritativeHealthy(report authority.Report) bool {
	return report.AuthConsistent &&
		report.HealthyAuth == report.TotalAuth &&
		report.HealthyRec == report.TotalRec
}

func verifyHealthy(report verify.Report) bool {
	return report.Errors == 0
}
