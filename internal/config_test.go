/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestLoadConfig(t *testing.T) {
	initializeTestDefaultConfig(t)
	_, err := loadConfig("../configs/config.default.yaml")
	if err != nil {
		t.Errorf("File configs/config.example.yaml is not parseable: %v", err)
	}
}

func TestMetricsAddressConfigDefaultAndOverride(t *testing.T) {
	initializeTestDefaultConfig(t)
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

func TestLoadConfigRejectsUnknownAndInvalidValues(t *testing.T) {
	initializeTestDefaultConfig(t)
	tests := []struct {
		name string
		body string
	}{
		{
			name: "unknown field",
			body: "server:\n  addres: 127.0.0.1:8642\n",
		},
		{
			name: "invalid log level",
			body: "server:\n  address: 127.0.0.1:8642\n  log-level: verbose\n",
		},
		{
			name: "invalid log format",
			body: "server:\n  address: 127.0.0.1:8642\n  log-format: xml\n",
		},
		{
			name: "empty listener",
			body: "server:\n  address: ''\n",
		},
		{
			name: "invalid resolver",
			body: "server:\n  address: 127.0.0.1:8642\ndns:\n  address: 127.0.0.1\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tt.body), 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := loadConfig(path); err == nil {
				t.Fatal("expected invalid configuration to be rejected")
			}
		})
	}
}

func initializeTestDefaultConfig(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile("../configs/config.default.yaml")
	if err != nil {
		t.Fatal(err)
	}
	SetDefaultConfig(data)
}

func TestResolvConfRetriesAfterInitialReadFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	rc := NewResolvConf(path)
	if rc == nil {
		t.Fatal("expected resolver cache object after initial read failure")
	}
	if cfg := rc.Get(); cfg != nil {
		t.Fatalf("expected missing resolver config before file exists, got %#v", cfg)
	}

	writeResolvConf(t, path, "127.0.0.1")
	assertResolvConfServer(t, rc.Get(), "127.0.0.1")
}

func TestResolvConfReloadsAfterAtomicReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	writeResolvConf(t, path, "127.0.0.1")
	rc := NewResolvConf(path)
	assertResolvConfServer(t, rc.Get(), "127.0.0.1")

	replaceResolvConf(t, path, "127.0.0.2")
	waitForResolvConfServer(t, rc, "127.0.0.2")

	replaceResolvConf(t, path, "127.0.0.3")
	waitForResolvConfServer(t, rc, "127.0.0.3")
}

func TestResolvConfReloadsAfterSymlinkTargetReplacement(t *testing.T) {
	dir := t.TempDir()
	targetDir := filepath.Join(dir, "run")
	if err := os.Mkdir(targetDir, 0755); err != nil {
		t.Fatalf("could not create target directory: %v", err)
	}
	target := filepath.Join(targetDir, "resolv.conf")
	link := filepath.Join(dir, "resolv.conf")
	writeResolvConf(t, target, "127.0.0.1")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("could not create resolv.conf symlink: %v", err)
	}
	rc := NewResolvConf(link)
	assertResolvConfServer(t, rc.Get(), "127.0.0.1")

	replaceResolvConf(t, target, "127.0.0.2")
	waitForResolvConfServer(t, rc, "127.0.0.2")
}

func writeResolvConf(t *testing.T, path string, server string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("nameserver "+server+"\n"), 0644); err != nil {
		t.Fatalf("could not write resolv.conf: %v", err)
	}
}

func replaceResolvConf(t *testing.T, path string, server string) {
	t.Helper()
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	writeResolvConf(t, tmp, server)
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("could not replace resolv.conf: %v", err)
	}
}

func waitForResolvConfServer(t *testing.T, rc *ResolvConf, server string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		cfg := rc.Get()
		if cfg != nil && len(cfg.Servers) > 0 && cfg.Servers[0] == server {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	assertResolvConfServer(t, rc.Get(), server)
}

func assertResolvConfServer(t *testing.T, cfg *dns.ClientConfig, server string) {
	t.Helper()
	if cfg == nil {
		t.Fatalf("expected resolver server %q, got nil config", server)
	}
	if len(cfg.Servers) == 0 {
		t.Fatalf("expected resolver server %q, got no servers", server)
	}
	if cfg.Servers[0] != server {
		t.Fatalf("expected resolver server %q, got %q", server, cfg.Servers[0])
	}
}
