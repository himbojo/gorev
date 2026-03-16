package main

import (
	"os"
	"strings"
)

// Config holds all configuration properties for the gorev application.
type Config struct {
	RedisAddr      string
	RedisPassword  string
	DataDir        string
	OCSPEndpoints  []string
	CRLEndpoints   []string
	CAEndpoints    []string
	ChainEndpoints []string
}

// LoadConfig reads the environment and sets up the configuration with defaults.
func LoadConfig() *Config {
	cfg := &Config{
		RedisAddr:     os.Getenv("REDIS_ADDR"),
		RedisPassword: os.Getenv("REDIS_PASSWORD"),
		DataDir:       os.Getenv("DATA_DIR"),
	}

	if cfg.RedisAddr == "" {
		cfg.RedisAddr = "localhost:6379"
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "."
	}

	cfg.OCSPEndpoints = parseEndpoints("ENDPOINTS_OCSP", "/ocsp")
	cfg.CRLEndpoints = parseEndpoints("ENDPOINTS_CRL", "/crls")
	cfg.CAEndpoints = parseEndpoints("ENDPOINTS_CA", "/cas")
	cfg.ChainEndpoints = parseEndpoints("ENDPOINTS_CHAIN", "")

	return cfg
}

// parseEndpoints reads a comma-separated list of URL paths from the given
// environment variable. If the variable is unset or empty, fallback is used.
// An empty fallback means the endpoint type is disabled by default.
func parseEndpoints(envVar, fallback string) []string {
	raw := os.Getenv(envVar)
	if raw == "" {
		if fallback == "" {
			return nil
		}
		raw = fallback
	}

	parts := strings.Split(raw, ",")
	var endpoints []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		endpoints = append(endpoints, p)
	}
	return endpoints
}
