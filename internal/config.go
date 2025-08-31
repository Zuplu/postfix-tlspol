/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

package tlspol

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/Zuplu/postfix-tlspol/internal/utils/log"

	"github.com/miekg/dns"
	"go.yaml.in/yaml/v4"
	"golang.org/x/sys/unix"
)

var defaultConfig = Config{}

type ServerConfig struct {
	Address           string `yaml:"address"`
	CacheFile         string `yaml:"cache-file"`
	NamedLogLevel     string `yaml:"log-level"`
	LogLevel          log.LogLevel
	SocketPermissions os.FileMode `yaml:"socket-permissions"`
	TlsRpt            bool        `yaml:"tlsrpt"`
	Prefetch          bool        `yaml:"prefetch"`
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
		log.Errorf("Reading from %q failed: %v", path, err)
		return nil
	}
	log.Infof("Read DNS configuration from %q", path)
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
		log.Errorf("InotifyInit() for /etc/resolv.conf failed: %v", err)
		return
	}
	_, err = unix.InotifyAddWatch(fd, rc.path, unix.IN_CLOSE_WRITE)
	if err != nil {
		log.Errorf("InotifyAddWatch() for /etc/resolv.conf failed: %v", err)
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
				log.Infof("Reloaded %q", rc.path)
			} else {
				log.Errorf("Failed to reload %q: %v", rc.path, err)
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
