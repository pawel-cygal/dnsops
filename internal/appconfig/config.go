package appconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Resolver          string              `yaml:"resolver" json:"resolver,omitempty"`
	Output            string              `yaml:"output" json:"output,omitempty"`
	Profiles          map[string][]string `yaml:"profiles" json:"profiles,omitempty"`
	PropagateProfiles []string            `yaml:"propagate_profiles" json:"propagate_profiles,omitempty"`
	CompareProfiles   []string            `yaml:"compare_profiles" json:"compare_profiles,omitempty"`
}

func DefaultPath() (string, error) {
	if v := strings.TrimSpace(os.Getenv("DNSOPS_CONFIG")); v != "" {
		return v, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "dnsops", "config.yaml"), nil
}

func Load(path string) (Config, error) {
	if strings.TrimSpace(path) == "" {
		var err error
		path, err = DefaultPath()
		if err != nil {
			return Config{}, err
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, nil
		}
		return Config{}, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	if err := validate(cfg); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func validate(cfg Config) error {
	switch strings.ToLower(strings.TrimSpace(cfg.Output)) {
	case "", "raw", "json", "yaml":
	default:
		return fmt.Errorf("output must be one of raw, json, yaml")
	}
	return nil
}
