/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

package main

import (
	"os"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Address  string `yaml:"address"`
	TlsRpt   bool   `yaml:"tlsrpt"`
	Prefetch bool   `yaml:"prefetch"`
}

func (c *ServerConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Set default values
	c.Address = defaultConfig.Server.Address
	c.TlsRpt = defaultConfig.Server.TlsRpt
	c.Prefetch = defaultConfig.Server.Prefetch
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

type RedisConfig struct {
	Disable  bool   `yaml:"disable"`
	Address  string `yaml:"address"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

func (c *RedisConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Set default values
	c.Disable = defaultConfig.Redis.Disable
	c.Address = defaultConfig.Redis.Address
	c.Password = defaultConfig.Redis.Password
	c.DB = defaultConfig.Redis.DB
	type alias RedisConfig
	if err := unmarshal((*alias)(c)); err != nil {
		return err
	}
	return nil
}

type Config struct {
	Server ServerConfig `yaml:"server"`
	Dns    DnsConfig    `yaml:"dns"`
	Redis  RedisConfig  `yaml:"redis"`
}

var defaultConfig = Config{
	Server: ServerConfig{
		Address:  "127.0.0.1:8642",
		TlsRpt:   false,
		Prefetch: true,
	},
	Dns: DnsConfig{
		Address: "127.0.0.53:53",
	},
	Redis: RedisConfig{
		Disable:  false,
		Address:  "127.0.0.1:6379",
		Password: "",
		DB:       2,
	},
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
