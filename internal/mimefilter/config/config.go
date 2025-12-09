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

// LoadConfig liest eine YAML-Datei und gibt die Konfiguration,
// die erlaubten MIME-Typen als Map sowie das Log-Level zurück
func LoadConfig(path string) (AppConfig, map[string]bool, int, error) {
	var cfg AppConfig
	file, err := os.Open(path)
	if err != nil {
		return cfg, nil, 0, err
	}
	defer file.Close()

	if err := yaml.NewDecoder(file).Decode(&cfg); err != nil {
		return cfg, nil, 0, err
	}

	setDefaults(&cfg)

	level := mapLogLevel(cfg.LogLevel)
	mimeMap := makeMimeMap(cfg.AllowedMimeTypes)

	return cfg, mimeMap, level, nil
}

func setDefaults(cfg *AppConfig) {
	if cfg.HeaderInspectSize <= 0 {
		cfg.HeaderInspectSize = 512
	}
	if cfg.ScannerBufferMB <= 0 {
		cfg.ScannerBufferMB = 10
	}
	if cfg.LogTag == "" {
		cfg.LogTag = "mime-filter"
	}
}

func mapLogLevel(level string) int {
	switch strings.ToLower(level) {
	case "debug":
		return 0
	case "warn":
		return 2
	case "error":
		return 3
	default:
		return 1 
	}
}

func makeMimeMap(mimeTypes []string) map[string]bool {
	m := make(map[string]bool)
	for _, mt := range mimeTypes {
		m[strings.ToLower(mt)] = true
	}
	return m
}
