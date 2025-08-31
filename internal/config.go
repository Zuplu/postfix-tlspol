/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

package tlspol

import (
	"fmt"
	"os"
	"strings"

	"github.com/Zuplu/postfix-tlspol/internal/utils/log"

	"github.com/miekg/dns"
	"go.yaml.in/yaml/v4"
)

var defaultConfig = Config{}

type ServerConfig struct {
	Address           string      `yaml:"address"`
	CacheFile         string      `yaml:"cache-file"`
	SocketPermissions os.FileMode `yaml:"socket-permissions"`
	TlsRpt            bool        `yaml:"tlsrpt"`
	Prefetch          bool        `yaml:"prefetch"`
	NamedLogLevel     string      `yaml:"log-level"`
	LogLevel          log.LogLevel
}

func (c *ServerConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
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
	c.LogLevel = log.LogLevels[strings.ToLower(c.NamedLogLevel)]
	return nil
}

type DnsConfig struct {
	Address *string `yaml:"address"`
}

func (c *DnsConfig) GetResolverAddress() (string, error) {
	if c.Address == nil {
		config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return "", fmt.Errorf("failed to read /etc/resolv.conf: %w", err)
		}
		if len(config.Servers) == 0 {
			return "", fmt.Errorf("no nameservers found in /etc/resolv.conf")
		}
		return config.Servers[0] + ":53", nil
	}
	return *c.Address, nil
}

func (c *DnsConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
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

func SetDefaultConfig(data *[]byte) {
	if err := yaml.Unmarshal(*data, &defaultConfig); err != nil {
		log.Errorf("Could not initialize default configuration: %v", err)
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
