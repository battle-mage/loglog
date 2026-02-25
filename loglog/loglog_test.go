package loglog

import (
	"log"
	"os"
	"path/filepath"
	"testing"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		name string
		in   int64
		want string
	}{
		{name: "bytes", in: 999, want: "999 B"},
		{name: "kilobytes", in: 1000, want: "1.0 kB"},
		{name: "megabytes", in: 1000 * 1000, want: "1.0 MB"},
		{name: "rounding", in: 1532, want: "1.5 kB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatBytes(tt.in); got != tt.want {
				t.Fatalf("formatBytes(%d) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestReadLoggingConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, configFileName)
	content := "log_file=app.log\nlog_to_console=0\n"
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	cfg := readLoggingConfig(cfgPath)
	if cfg.logFile != "app.log" {
		t.Fatalf("unexpected log file config: %+v", cfg)
	}
	if cfg.logToConsole == nil || *cfg.logToConsole {
		t.Fatalf("unexpected console config: %+v", cfg)
	}
}

func TestReadLoggingConfig_MissingConsoleKey(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, configFileName)
	if err := os.WriteFile(cfgPath, []byte("log_file=app.log\n"), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	cfg := readLoggingConfig(cfgPath)
	if cfg.logToConsole != nil {
		t.Fatalf("expected logToConsole=nil when key missing, got: %+v", cfg)
	}
}

func TestBuildConfiguredLogger_ConfigOnlyFile(t *testing.T) {
	dir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() { _ = os.Chdir(oldWD) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	if err := os.WriteFile(configFileName, []byte("log_file=app.log\nlog_to_console=0\n"), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	fallback := log.New(os.Stderr, "", 0)
	logger := buildConfiguredLogger(&Options{}, fallback)
	logger.Println("hello")

	data, err := os.ReadFile(filepath.Join(dir, "app.log"))
	if err != nil {
		t.Fatalf("read app.log: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected app.log to contain output")
	}
}

func TestBuildConfiguredLogger_OptionsOverrideConfig(t *testing.T) {
	dir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() { _ = os.Chdir(oldWD) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	if err := os.WriteFile(configFileName, []byte("log_file=cfg.log\nlog_to_console=0\n"), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	logToConsole := false
	logFile := ""
	opts := &Options{LogToConsole: &logToConsole, LogFile: &logFile}
	fallback := log.New(os.Stderr, "", 0)
	logger := buildConfiguredLogger(opts, fallback)
	logger.Println("dropped")

	if _, err := os.Stat(filepath.Join(dir, "cfg.log")); !os.IsNotExist(err) {
		t.Fatalf("cfg.log should not be created, got err=%v", err)
	}
}
