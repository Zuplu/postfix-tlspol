/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	_, err := loadConfig("../configs/config.default.yaml")
	if err != nil {
		t.Errorf("File configs/config.example.yaml is not parseable: %v", err)
	}
}

func TestMetricsAddressConfigDefaultAndOverride(t *testing.T) {
	cfg, err := loadConfig("../configs/config.default.yaml")
	if err != nil {
		t.Fatalf("default config is not parseable: %v", err)
	}
	if cfg.Server.MetricsAddress != "" {
		t.Fatalf("expected metrics-address to default to empty, got %q", cfg.Server.MetricsAddress)
	}

	path := filepath.Join(t.TempDir(), "config.yaml")
	err = os.WriteFile(path, []byte(`
server:
  address: 127.0.0.1:8642
  metrics-address: unix:/tmp/postfix-tlspol-metrics.sock
dns:
`), 0644)
	if err != nil {
		t.Fatalf("could not write test config: %v", err)
	}

	cfg, err = loadConfig(path)
	if err != nil {
		t.Fatalf("config with metrics-address is not parseable: %v", err)
	}
	if cfg.Server.MetricsAddress != "unix:/tmp/postfix-tlspol-metrics.sock" {
		t.Fatalf("unexpected metrics-address: %q", cfg.Server.MetricsAddress)
	}
}
