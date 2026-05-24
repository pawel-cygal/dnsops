package main

import (
	"strings"
	"sync"

	"dnsops/internal/appconfig"
)

var (
	cfgOnce sync.Once
	cfgVal  appconfig.Config
	cfgErr  error
)

func currentConfig() appconfig.Config {
	cfgOnce.Do(func() {
		cfgVal, cfgErr = appconfig.Load("")
	})
	if cfgErr != nil {
		fatal(cfgErr.Error())
	}
	return cfgVal
}

func defaultResolver() string {
	if v := strings.TrimSpace(currentConfig().Resolver); v != "" {
		return v
	}
	return "1.1.1.1:53"
}

func defaultOutput() string {
	return strings.ToLower(strings.TrimSpace(currentConfig().Output))
}
