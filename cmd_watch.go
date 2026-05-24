package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"dnsops/internal/authority"
	"dnsops/internal/compare"
	"dnsops/internal/propagation"
	"dnsops/internal/verify"
)

type watchConfig struct {
	Enabled       bool
	UntilOK       bool
	Interval      time.Duration
	Timeout       time.Duration
	MaxIterations int
}

type watchIteration struct {
	Result  any
	Healthy bool
	Render  func()
}

type watchStopError struct {
	msg string
}

func (e watchStopError) Error() string { return e.msg }

type outputFormat string

const (
	outputRaw  outputFormat = "raw"
	outputJSON outputFormat = "json"
	outputYAML outputFormat = "yaml"
)

type watchEnvelope struct {
	Timestamp string `json:"timestamp" yaml:"timestamp"`
	Iteration int    `json:"iteration" yaml:"iteration"`
	Result    any    `json:"result" yaml:"result"`
	Error     string `json:"error,omitempty" yaml:"error,omitempty"`
}

func normalizeWatchConfig(enabled, untilOK bool, interval, timeout time.Duration, maxIterations int) (watchConfig, error) {
	if untilOK {
		enabled = true
	}
	if !enabled {
		return watchConfig{
			Enabled:       false,
			UntilOK:       untilOK,
			Interval:      interval,
			Timeout:       timeout,
			MaxIterations: maxIterations,
		}, nil
	}
	if interval <= 0 {
		return watchConfig{}, fmt.Errorf("interval must be > 0")
	}
	if timeout < 0 {
		return watchConfig{}, fmt.Errorf("timeout must be >= 0")
	}
	if maxIterations < 0 {
		return watchConfig{}, fmt.Errorf("max-iterations must be >= 0")
	}
	return watchConfig{
		Enabled:       true,
		UntilOK:       untilOK,
		Interval:      interval,
		Timeout:       timeout,
		MaxIterations: maxIterations,
	}, nil
}

func watchLoop(cfg watchConfig, label string, jsonOut bool, run func() (watchIteration, error)) error {
	format := outputRaw
	if jsonOut {
		format = outputJSON
	}
	return watchLoopFormat(cfg, label, format, run)
}

func watchLoopFormat(cfg watchConfig, label string, format outputFormat, run func() (watchIteration, error)) error {
	live := format == outputRaw && ttyStdout()
	start := time.Now()
	if live {
		fmt.Print("\x1b[?25l")
		defer fmt.Print("\x1b[?25h")
	}
	for iteration := 1; ; iteration++ {
		step, err := run()
		now := time.Now()
		switch format {
		case outputJSON:
			env := watchEnvelope{
				Timestamp: now.UTC().Format(time.RFC3339),
				Iteration: iteration,
			}
			if err != nil {
				env.Error = err.Error()
			} else {
				env.Result = step.Result
			}
			printJSONLine(env)
		case outputYAML:
			if iteration > 1 {
				fmt.Println("---")
			}
			env := watchEnvelope{
				Timestamp: now.UTC().Format(time.RFC3339),
				Iteration: iteration,
			}
			if err != nil {
				env.Error = err.Error()
			} else {
				env.Result = step.Result
			}
			printYAML(env)
		default:
			if live {
				fmt.Print("\x1b[H\x1b[2J")
			}
			fmt.Printf("[%s] %s\n\n", now.Format("2006-01-02 15:04:05"), label)
			if err != nil {
				fmt.Printf("error: %s\n\n", err)
			} else {
				step.Render()
				fmt.Println()
			}
		}
		if err == nil && cfg.UntilOK && step.Healthy {
			return nil
		}
		if cfg.MaxIterations > 0 && iteration >= cfg.MaxIterations {
			return watchStopError{msg: fmt.Sprintf("watch stopped after %d iterations without reaching a healthy state", cfg.MaxIterations)}
		}
		if cfg.Timeout > 0 && time.Since(start) >= cfg.Timeout {
			return watchStopError{msg: fmt.Sprintf("watch timed out after %s without reaching a healthy state", cfg.Timeout)}
		}
		time.Sleep(cfg.Interval)
	}
}

func handleWatchError(err error) {
	if err == nil {
		return
	}
	var stopErr watchStopError
	if errors.As(err, &stopErr) {
		fmt.Fprintln(os.Stderr, "dnsops:", err)
		exitCode(1)
	}
	fatal(err.Error())
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
