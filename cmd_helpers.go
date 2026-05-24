package main

import (
	"encoding/json"
	"os"

	"gopkg.in/yaml.v3"
)

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fatal(err.Error())
	}
}

func printYAML(v any) {
	data, err := yaml.Marshal(v)
	if err != nil {
		fatal(err.Error())
	}
	if _, err := os.Stdout.Write(data); err != nil {
		fatal(err.Error())
	}
}
