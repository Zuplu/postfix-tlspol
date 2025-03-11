/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

package tlspol

import (
	"os"

	"github.com/Zuplu/postfix-tlspol/internal/utils/log"
	"gopkg.in/yaml.v3"
)

var defaultConfig = Config{}

type ServerConfig struct {
	Address           string      `yaml:"address"`
	CacheFile         string      `yaml:"cache-file"`
	SocketPermissions os.FileMode `yaml:"socket-permissions"`
	TlsRpt            bool        `yaml:"tlsrpt"`
	Prefetch          bool        `yaml:"prefetch"`
}

func (c *ServerConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Set default values
	c.Address = defaultConfig.Server.Address
	c.SocketPermissions = defaultConfig.Server.SocketPermissions
	c.TlsRpt = defaultConfig.Server.TlsRpt
	c.Prefetch = defaultConfig.Server.Prefetch
	c.CacheFile = defaultConfig.Server.CacheFile
	type alias ServerConfig
	if err := unmarshal((*alias)(c)); err != nil {
		return err
	}
	return nil
}

type DnsConfig struct {
	Address string `yaml:"address"`
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
