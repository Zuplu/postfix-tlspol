/*
 * MIT License
 * Copyright (c) 2024 Zuplu
 */

package main

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type ServerConfig struct {
	Address  string `yaml:"address"`
	TlsRpt   bool   `yaml:"tlsrpt"`
	Prefetch bool   `yaml:"prefetch"`
}

func (c *ServerConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Set default values
	c.Address = "127.0.0.1:8642"
	c.TlsRpt = false
	c.Prefetch = false
	type plain ServerConfig
	if err := unmarshal((*plain)(c)); err != nil {
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
	type plain DnsConfig
	if err := unmarshal((*plain)(c)); err != nil {
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
	type plain RedisConfig
	if err := unmarshal((*plain)(c)); err != nil {
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
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return Config{}, err
	}

	var config Config
	return config, yaml.Unmarshal(data, &config)
}
