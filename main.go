package main

import (
	_ "embed"
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
	tlspol.SetDefaultConfig(&defaultConfigYaml)
	tlspol.StartDaemon(&Version, &LicenseText)
}
