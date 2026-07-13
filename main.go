/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package main

import (
	_ "embed"

	"log/slog"
	"os"
	"regexp"
	"runtime/debug"
	"strings"

	"github.com/Zuplu/postfix-tlspol/internal"
)

var (
	Version string = "undefined"
	//go:embed LICENSE
	LicenseText string
	//go:embed configs/config.default.yaml
	defaultConfigYaml []byte
)

func cleanVersion(raw string) string {
	re := regexp.MustCompile(`^v?(\d+\.\d+\.\d+)(?:-[\d.]+-[a-f0-9]+)?(?:\+.*dirty)?$`)
	match := re.FindStringSubmatch(raw)
	if len(match) >= 2 {
		base := match[1]
		if strings.Contains(raw, "dirty") || strings.Contains(raw, "-0.") {
			return base + "-dev"
		}
		return base
	}
	return raw
}

func init() {
	if Version == "undefined" || len(Version) == 0 {
		if info, ok := debug.ReadBuildInfo(); ok {
			if info.Main.Version != "" {
				Version = info.Main.Version
			}
		}
	}
	Version = cleanVersion(Version)
	Version = strings.TrimPrefix(Version, "v")
}

func main() {
	tlspol.SetDefaultConfig(defaultConfigYaml)
	if err := tlspol.StartDaemon(Version, LicenseText); err != nil {
		slog.Error("postfix-tlspol terminated", "error", err)
		os.Exit(1)
	}
}
