package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func mergeTargets(args []string, inputPath string) ([]string, error) {
	out := append([]string(nil), args...)
	if strings.TrimSpace(inputPath) == "" {
		return out, nil
	}
	file, err := os.Open(inputPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no targets found")
	}
	return out, nil
}
