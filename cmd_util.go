package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// normalizeFlagArgs moves recognized flags (and their values, when separate)
// ahead of positional args so stdlib flag.FlagSet can parse a more human CLI:
// `cmd name type --json` becomes `cmd --json name type`.
func normalizeFlagArgs(args []string, valueFlags map[string]bool) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			flags = append(flags, arg)
			if strings.Contains(arg, "=") {
				continue
			}
			if valueFlags[arg] && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		pos = append(pos, arg)
	}
	return append(flags, pos...)
}

func ttyStdout() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func colorEnabled() bool {
	return ttyStdout() && strings.TrimSpace(os.Getenv("NO_COLOR")) == ""
}

func colorize(s, code string) string {
	if !colorEnabled() {
		return s
	}
	return code + s + "\x1b[0m"
}

func statusColor(status string) string {
	switch status {
	case "ok", "signed":
		return colorize(status, "\x1b[32m")
	case "warn", "stale", "split":
		return colorize(status, "\x1b[33m")
	case "error", "fail", "broken", "diff", "critical":
		return colorize(status, "\x1b[31m")
	default:
		return status
	}
}

func padRule(width int) string {
	if width <= 0 {
		return ""
	}
	return strings.Repeat("─", width)
}

func renderTable(headers []string, rows [][]string) {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && visibleLen(cell) > widths[i] {
				widths[i] = visibleLen(cell)
			}
		}
	}
	for i, h := range headers {
		if i > 0 {
			fmt.Print("  ")
		}
		fmt.Printf("%-*s", widths[i], h)
	}
	fmt.Println()
	for i, w := range widths {
		if i > 0 {
			fmt.Print("  ")
		}
		fmt.Print(padRule(w))
	}
	fmt.Println()
	for _, row := range rows {
		for i, cell := range row {
			if i > 0 {
				fmt.Print("  ")
			}
			fmt.Printf("%-*s", widths[i]+len(cell)-visibleLen(cell), cell)
		}
		fmt.Println()
	}
}

func resolveOutputFormat(jsonOut, yamlOut bool) (outputFormat, error) {
	if jsonOut && yamlOut {
		return "", fmt.Errorf("--json and --yaml are mutually exclusive")
	}
	if jsonOut {
		return outputJSON, nil
	}
	if yamlOut {
		return outputYAML, nil
	}
	switch defaultOutput() {
	case "json":
		return outputJSON, nil
	case "yaml":
		return outputYAML, nil
	default:
		return outputRaw, nil
	}
}

func visibleLen(s string) int {
	return len(ansiPattern.ReplaceAllString(s, ""))
}
