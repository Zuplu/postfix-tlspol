package main

import (
	_ "embed"
	"github.com/Zuplu/postfix-tlspol/internal"
	"regexp"
	"runtime/debug"
	"strings"
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
	return "0.0.0"
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
	if strings.HasPrefix(Version, "v") {
		Version = Version[1:]
	}
}

func main() {
	tlspol.SetDefaultConfig(&defaultConfigYaml)
	tlspol.StartDaemon(&Version, &LicenseText)
}
