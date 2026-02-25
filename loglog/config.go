package loglog

import (
	"bufio"
	"io"
	"log"
	"os"
	"strings"
)

const configFileName = "loglog.cfg"

type loggingConfig struct {
	logFile      string
	logToConsole *bool
}

func buildConfiguredLogger(opts *Options, fallback *log.Logger) *log.Logger {
	cfg := readLoggingConfig(configFileName)

	logToConsole := true
	if cfg.logToConsole != nil {
		logToConsole = *cfg.logToConsole
	}
	if opts.LogToConsole != nil {
		logToConsole = *opts.LogToConsole
	}

	logFile := cfg.logFile
	if opts.LogFile != nil {
		logFile = *opts.LogFile
	}

	writers := make([]io.Writer, 0, 2)
	if logToConsole {
		writers = append(writers, os.Stderr)
	}
	if logFile != "" {
		file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			writers = append(writers, file)
		} else {
			fallback.Printf("loglog: cannot open log_file %q: %v", logFile, err)
		}
	}

	if len(writers) == 0 {
		return log.New(io.Discard, "", log.LstdFlags)
	}
	if len(writers) == 1 {
		return log.New(writers[0], "", log.LstdFlags)
	}
	return log.New(io.MultiWriter(writers...), "", log.LstdFlags)
}

func readLoggingConfig(path string) loggingConfig {
	file, err := os.Open(path)
	if err != nil {
		return loggingConfig{}
	}
	defer file.Close()

	var cfg loggingConfig
	s := bufio.NewScanner(file)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "log_file":
			cfg.logFile = val
		case "log_to_console":
			v := parseBoolValue(val)
			cfg.logToConsole = &v
		}
	}

	return cfg
}

func parseBoolValue(v string) bool {
	v = strings.TrimSpace(v)
	return v == "1" || strings.EqualFold(v, "true")
}
