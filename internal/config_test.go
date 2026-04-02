/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"testing"
)

func TestLoadConfig(t *testing.T) {
	_, err := loadConfig("../configs/config.default.yaml")
	if err != nil {
		t.Errorf("File configs/config.example.yaml is not parseable: %v", err)
	}
}
