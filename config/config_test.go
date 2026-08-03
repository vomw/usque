package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveConfigCreatesParentDirectories(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "nested", "dir", "config.json")

	cfg := Config{
		PrivateKey: "abc",
	}

	if err := cfg.SaveConfig(configPath); err != nil {
		t.Fatalf("SaveConfig returned error: %v", err)
	}

	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("expected config file to exist: %v", err)
	}

	if _, err := os.Stat(filepath.Dir(configPath)); err != nil {
		t.Fatalf("expected parent directory to exist: %v", err)
	}
}
