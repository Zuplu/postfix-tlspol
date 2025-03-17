package main

import (
	_ "embed"
	"runtime/debug"
	"github.com/Zuplu/postfix-tlspol/internal"
)

var (
	Version string
	//go:embed LICENSE
	LicenseText string
	//go:embed configs/config.default.yaml
	defaultConfigYaml []byte
)

func main() {
    debug.SetGCPercent(300) // make GC run less often, save CPU cycles
    debug.SetMemoryLimit(32 * 1024 * 1024) // set soft memory limit when to trigger GC
	tlspol.SetDefaultConfig(&defaultConfigYaml)
	tlspol.StartDaemon(&Version, &LicenseText)
}
