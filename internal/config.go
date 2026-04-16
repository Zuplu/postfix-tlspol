/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"go.yaml.in/yaml/v4"
	"golang.org/x/sys/unix"
)

var defaultConfig = Config{}

type ServerConfig struct {
	Address           string `yaml:"address"`
	CacheFile         string `yaml:"cache-file"`
	NamedLogLevel     string `yaml:"log-level"`
	LogLevel          slog.Level
	LogFormat         string      `yaml:"log-format"`
	SocketPermissions os.FileMode `yaml:"socket-permissions"`
	TlsRpt            bool        `yaml:"tlsrpt"`
	Prefetch          bool        `yaml:"prefetch"`
}

func (c *ServerConfig) UnmarshalYAML(unmarshal func(any) error) error {
	// Set default values
	c.Address = defaultConfig.Server.Address
	c.SocketPermissions = defaultConfig.Server.SocketPermissions
	c.NamedLogLevel = defaultConfig.Server.NamedLogLevel
	c.TlsRpt = false
	c.Prefetch = defaultConfig.Server.Prefetch
	c.CacheFile = defaultConfig.Server.CacheFile
	type alias ServerConfig
	if err := unmarshal((*alias)(c)); err != nil {
		return err
	}
	var lvl slog.Level
	err := lvl.UnmarshalText([]byte(strings.ToLower(c.NamedLogLevel)))
	if err != nil {
		lvl = slog.LevelInfo
	}
	c.LogLevel = lvl
	return nil
}

type DnsConfig struct {
	Address *string `yaml:"address"`
}

type ResolvConf struct {
	config *dns.ClientConfig
	path   string
	sync.RWMutex
}

var resolvConf = sync.OnceValue(func() *ResolvConf {
	return NewResolvConf("/etc/resolv.conf")
})

func NewResolvConf(path string) *ResolvConf {
	cfg, err := dns.ClientConfigFromFile(path)
	if err != nil {
		slog.Error("Reading DNS configuration failed", "path", path, "error", err)
		return nil
	}
	slog.Info("Read DNS configuration", "path", path)
	rc := &ResolvConf{
		config: cfg,
		path:   path,
	}
	go rc.watch()
	return rc
}

func (rc *ResolvConf) Get() *dns.ClientConfig {
	rc.RLock()
	defer rc.RUnlock()
	return rc.config
}

func (rc *ResolvConf) watch() {
	fd, err := unix.InotifyInit()
	if err != nil {
		slog.Error("InotifyInit() failed", "path", rc.path, "error", err)
		return
	}
	_, err = unix.InotifyAddWatch(fd, rc.path, unix.IN_CLOSE_WRITE)
	if err != nil {
		slog.Error("InotifyAddWatch() failed", "path", rc.path, "error", err)
		return
	}
	buf := make([]byte, 4096)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			continue
		}
		if n > 0 {
			cfg, err := dns.ClientConfigFromFile(rc.path)
			if err == nil {
				rc.Lock()
				rc.config = cfg
				rc.Unlock()
				slog.Info("Reloaded DNS configuration", "path", rc.path)
			} else {
				slog.Error("Failed to reload DNS configuration", "path", rc.path, "error", err)
			}
		}
	}
}

func (c *DnsConfig) GetResolverAddress() (string, error) {
	if c.Address == nil {
		rc := resolvConf()
		if rc == nil {
			return "", fmt.Errorf("could not load /etc/resolv.conf")
		}
		config := rc.Get()
		if len(config.Servers) == 0 {
			return "", fmt.Errorf("no nameservers found in /etc/resolv.conf")
		}
		return net.JoinHostPort(config.Servers[0], "53"), nil
	}
	return *c.Address, nil
}

func (c *DnsConfig) UnmarshalYAML(unmarshal func(any) error) error {
	// Set default values
	c.Address = defaultConfig.Dns.Address
	type alias DnsConfig
	if err := unmarshal((*alias)(c)); err != nil {
		return err
	}
	return nil
}

type Config struct {
	Dns    DnsConfig    `yaml:"dns"`
	Server ServerConfig `yaml:"server"`
}

func SetDefaultConfig(data []byte) {
	if err := yaml.Unmarshal(data, &defaultConfig); err != nil {
		slog.Error("Could not initialize default configuration", "error", err)
	}
}

func loadConfig(filename string) (Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		config := defaultConfig
		return config, err
	}

	var config Config
	return config, yaml.Unmarshal(data, &config)
}
