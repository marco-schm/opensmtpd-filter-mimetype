package config

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type AppConfig struct {
	LogTag            string   `yaml:"log_tag"`
	LogLevel          string   `yaml:"log_level"`
	ScannerBufferMB   int      `yaml:"scanner_buffer_max_mb"`
	AllowedMimeTypes  []string `yaml:"allowed_mime_types"`
	MaxInspectBytes   int      `yaml:"max_inspect_bytes"`
	HeaderInspectSize int      `yaml:"header_inspect_size"`
}

// LoadConfig liest die YAML-Konfiguration, erstellt die MIME-Whitelist und
// gibt den numerischen Log-Level zurück
func LoadConfig(path string) (AppConfig, map[string]bool, int, error) {
	var cfg AppConfig

	file, err := os.Open(path)
	if err != nil {
		return cfg, nil, 0, err
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, nil, 0, err
	}

	if cfg.HeaderInspectSize <= 0 {
		cfg.HeaderInspectSize = 512
	}
	if cfg.ScannerBufferMB <= 0 {
		cfg.ScannerBufferMB = 10
	}
	if cfg.LogTag == "" {
		cfg.LogTag = "mx-generic-filter"
	}

	// Log-Level Mapping
	level := 1 // info default
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = 0
	case "warn":
		level = 2
	case "error":
		level = 3
	}

	// MIME-Whitelist
	mimeMap := make(map[string]bool)
	for _, m := range cfg.AllowedMimeTypes {
		mimeMap[strings.ToLower(m)] = true
	}

	return cfg, mimeMap, level, nil
}
