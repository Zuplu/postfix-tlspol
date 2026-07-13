/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"github.com/miekg/dns"
	"go.yaml.in/yaml/v4"
	"golang.org/x/sys/unix"
)

var defaultConfig = Config{}

const CONFIG_MAX_SIZE = 1 << 20

type ServerConfig struct {
	Address           string `yaml:"address"`
	MetricsAddress    string `yaml:"metrics-address"`
	CacheFile         string `yaml:"cache-file"`
	NamedLogLevel     string `yaml:"log-level"`
	LogFormat         string `yaml:"log-format"`
	LogLevel          slog.Level
	SocketPermissions os.FileMode `yaml:"socket-permissions"`
	TlsRpt            bool        `yaml:"tlsrpt"`
	Prefetch          bool        `yaml:"prefetch"`
}

func (c *ServerConfig) UnmarshalYAML(unmarshal func(any) error) error {
	// Set default values
	c.Address = defaultConfig.Server.Address
	c.MetricsAddress = defaultConfig.Server.MetricsAddress
	c.SocketPermissions = defaultConfig.Server.SocketPermissions
	c.NamedLogLevel = defaultConfig.Server.NamedLogLevel
	c.LogFormat = defaultConfig.Server.LogFormat
	c.TlsRpt = false
	c.Prefetch = defaultConfig.Server.Prefetch
	c.CacheFile = defaultConfig.Server.CacheFile
	type alias ServerConfig
	if err := unmarshal((*alias)(c)); err != nil {
		return err
	}
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(strings.ToLower(c.NamedLogLevel))); err != nil {
		return fmt.Errorf("invalid server.log-level %q: %w", c.NamedLogLevel, err)
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

type resolvConfWatcher struct {
	rc     *ResolvConf
	dir    string
	base   string
	fd     int
	dirWD  int
	fileWD int
}

var resolvConf = sync.OnceValue(func() *ResolvConf {
	return NewResolvConf("/etc/resolv.conf")
})

func NewResolvConf(path string) *ResolvConf {
	rc := &ResolvConf{
		path: path,
	}
	rc.load("Read DNS configuration")
	rc.startWatch()
	return rc
}

func (rc *ResolvConf) Get() *dns.ClientConfig {
	rc.RLock()
	cfg := rc.config
	rc.RUnlock()
	if cfg != nil {
		return cfg
	}
	rc.load("Read DNS configuration")
	rc.RLock()
	defer rc.RUnlock()
	return rc.config
}

func (rc *ResolvConf) load(successMessage string) bool {
	cfg, err := dns.ClientConfigFromFile(rc.path)
	if err != nil {
		slog.Error("Reading DNS configuration failed", "path", rc.path, "error", err)
		return false
	}
	rc.Lock()
	rc.config = cfg
	rc.Unlock()
	slog.Info(successMessage, "path", rc.path)
	return true
}

func (rc *ResolvConf) startWatch() {
	fd, err := unix.InotifyInit()
	if err != nil {
		slog.Error("InotifyInit() failed", "path", rc.path, "error", err)
		return
	}
	watcher := &resolvConfWatcher{
		rc:   rc,
		fd:   fd,
		dir:  filepath.Dir(rc.path),
		base: filepath.Base(rc.path),
	}
	if err := watcher.addDirWatch(); err != nil {
		slog.Error("InotifyAddWatch() failed", "path", watcher.dir, "error", err)
		_ = unix.Close(fd)
		return
	}
	watcher.addFileWatch()
	go watcher.watch()
}

func (w *resolvConfWatcher) addDirWatch() error {
	wd, err := unix.InotifyAddWatch(w.fd, w.dir, unix.IN_CLOSE_WRITE|unix.IN_CREATE|unix.IN_MOVED_TO|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF|unix.IN_ONLYDIR)
	if err != nil {
		return err
	}
	w.dirWD = wd
	return nil
}

func (w *resolvConfWatcher) addFileWatch() {
	wd, err := unix.InotifyAddWatch(w.fd, w.rc.path, unix.IN_CLOSE_WRITE|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF)
	if err != nil {
		slog.Warn("InotifyAddWatch() failed", "path", w.rc.path, "error", err)
		return
	}
	w.fileWD = wd
}

func (w *resolvConfWatcher) watch() {
	defer unix.Close(w.fd)
	buf := make([]byte, 4096)
	for {
		n, err := unix.Read(w.fd, buf)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			slog.Error("Reading resolver configuration watch failed", "path", w.rc.path, "error", err)
			return
		}
		w.handleEvents(buf[:n])
	}
}

func (w *resolvConfWatcher) handleEvents(data []byte) {
	for len(data) >= unix.SizeofInotifyEvent {
		event := (*unix.InotifyEvent)(unsafe.Pointer(&data[0]))
		if event.Len > uint32(len(data)-unix.SizeofInotifyEvent) {
			return
		}
		eventLen := unix.SizeofInotifyEvent + int(event.Len)
		name := ""
		if event.Len > 0 {
			nameBytes := data[unix.SizeofInotifyEvent:eventLen]
			if nul := bytes.IndexByte(nameBytes, 0); nul >= 0 {
				nameBytes = nameBytes[:nul]
			}
			name = string(nameBytes)
		}
		w.handleEvent(int(event.Wd), event.Mask, name)
		data = data[eventLen:]
	}
}

func (w *resolvConfWatcher) handleEvent(wd int, mask uint32, name string) {
	isFileEvent := wd == w.fileWD
	isPathEvent := isFileEvent || (wd == w.dirWD && name == w.base)
	if !isPathEvent {
		return
	}
	if isFileEvent && mask&(unix.IN_IGNORED|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF) != 0 {
		w.fileWD = 0
	}
	if mask&(unix.IN_CREATE|unix.IN_MOVED_TO|unix.IN_IGNORED|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF) != 0 {
		w.addFileWatch()
	}
	if mask&(unix.IN_CLOSE_WRITE|unix.IN_MOVED_TO|unix.IN_IGNORED|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF) != 0 {
		w.rc.load("Reloaded DNS configuration")
	}
}

func (c *DnsConfig) GetResolverAddress() (string, error) {
	if c.Address == nil {
		rc := resolvConf()
		if rc == nil {
			return "", fmt.Errorf("could not load /etc/resolv.conf")
		}
		config := rc.Get()
		if config == nil {
			return "", fmt.Errorf("resolver configuration is unavailable")
		}
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
	f, err := os.Open(filename)
	if err != nil {
		config := defaultConfig
		return config, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, CONFIG_MAX_SIZE+1))
	if err != nil {
		return Config{}, err
	}
	if len(data) > CONFIG_MAX_SIZE {
		return Config{}, fmt.Errorf("configuration exceeds %d bytes", CONFIG_MAX_SIZE)
	}

	var config Config
	if err := yaml.Load(data, &config, yaml.WithKnownFields()); err != nil {
		return config, err
	}
	if err := validateConfig(&config); err != nil {
		return config, err
	}
	return config, nil
}

func validateConfig(config *Config) error {
	config.Server.Address = strings.TrimSpace(config.Server.Address)
	config.Server.MetricsAddress = strings.TrimSpace(config.Server.MetricsAddress)
	config.Server.CacheFile = strings.TrimSpace(config.Server.CacheFile)
	if err := validateListenAddress("server.address", config.Server.Address, false); err != nil {
		return err
	}
	if err := validateListenAddress("server.metrics-address", config.Server.MetricsAddress, true); err != nil {
		return err
	}
	if config.Server.CacheFile == "" {
		return fmt.Errorf("server.cache-file must not be empty")
	}
	if config.Server.SocketPermissions&^os.ModePerm != 0 {
		return fmt.Errorf("server.socket-permissions contains unsupported mode bits")
	}
	config.Server.LogFormat = strings.ToLower(strings.TrimSpace(config.Server.LogFormat))
	if config.Server.LogFormat != "text" && config.Server.LogFormat != "json" {
		return fmt.Errorf("invalid server.log-format %q", config.Server.LogFormat)
	}
	if config.Dns.Address != nil {
		address := strings.TrimSpace(*config.Dns.Address)
		if _, _, err := net.SplitHostPort(address); err != nil {
			return fmt.Errorf("invalid dns.address %q: %w", address, err)
		}
		config.Dns.Address = &address
	}
	return nil
}

func validateListenAddress(name string, address string, allowEmpty bool) error {
	address = strings.TrimSpace(address)
	if address == "" {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("%s must not be empty", name)
	}
	if strings.HasPrefix(address, "unix:") {
		if strings.TrimSpace(address[5:]) == "" {
			return fmt.Errorf("%s has an empty Unix socket path", name)
		}
		return nil
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return fmt.Errorf("invalid %s %q: %w", name, address, err)
	}
	return nil
}
