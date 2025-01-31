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
	Strict   bool   `yaml:"strict"`
}

func (c *ServerConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Set default values
	c.Address = "127.0.0.1:8642"
	c.TlsRpt = false
	c.Prefetch = true
	c.Strict = false
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
	c.Address = "127.0.0.53:53"
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
	c.Disable = false
	c.Address = "127.0.0.1:6379"
	c.Password = ""
	c.DB = 2
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

func loadConfig(filename string) (Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return Config{}, err
	}

	var config Config
	return config, yaml.Unmarshal(data, &config)
}
