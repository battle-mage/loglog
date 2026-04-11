package loglog

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestReadLoggingConfig_BotTag(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, configFileName)
	if err := os.WriteFile(cfgPath, []byte("bot_tag=@BOT@\n"), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	cfg := readLoggingConfig(cfgPath)
	if cfg.botTag == nil || *cfg.botTag != "@BOT@" {
		t.Fatalf("unexpected bot_tag config: %+v", cfg)
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

func TestApplyDefaults_UsesConfiguredLoggerWhenDefaultLoggerProvided(t *testing.T) {
	dir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() { _ = os.Chdir(oldWD) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	if err := os.WriteFile(configFileName, []byte("log_file=default.log\nlog_to_console=0\n"), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	opts := Options{Logger: log.Default()}
	applyDefaults(&opts)
	opts.Logger.Println("hello")

	data, err := os.ReadFile(filepath.Join(dir, "default.log"))
	if err != nil {
		t.Fatalf("read default.log: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected default.log to contain output")
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

func TestApplyDefaults_BotTagEmptyStringFromConfigDisablesTagging(t *testing.T) {
	dir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() { _ = os.Chdir(oldWD) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	if err := os.WriteFile(configFileName, []byte("bot_tag=\n"), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	opts := Options{}
	applyDefaults(&opts)
	if opts.BotTag == nil {
		t.Fatal("expected BotTag to be set")
	}
	if *opts.BotTag != "" {
		t.Fatalf("expected empty bot_tag to disable tagging, got: %q", *opts.BotTag)
	}
}

func TestIsBotUserAgent(t *testing.T) {
	tests := []struct {
		ua   string
		want bool
	}{
		{ua: "Mozilla/5.0 AppleWebKit Safari", want: false},
		{ua: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", want: true},
		{ua: "ClaudeBot/1.0 (+https://www.anthropic.com/claudebot)", want: true},
		{ua: "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", want: true},
		{ua: "Mozilla/5.0 (compatible; DotBot/1.2; +http://opensiteexplorer.org/dotbot, help@moz.com)", want: true},
		{ua: "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)", want: true},
		{ua: "Mozilla/5.0 (compatible; PetalBot; +https://webmaster.petalsearch.com/site/petalbot)", want: true},
		{ua: "Mozilla/5.0 (compatible; Bytespider; +https://http://bytespider/)", want: true},
	}

	for _, tt := range tests {
		if got := isBotUserAgent(tt.ua); got != tt.want {
			t.Fatalf("isBotUserAgent(%q)=%v, want %v", tt.ua, got, tt.want)
		}
	}
}

func TestMiddleware_AppendsBotTag(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	tag := "@BOT@"
	opts := DefaultOptions()
	opts.Logger = logger
	opts.SkipLoopback = false
	opts.BotTag = &tag

	h := New(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := buf.String(); !strings.Contains(got, "| @BOT@") {
		t.Fatalf("expected bot tag in log row, got: %q", got)
	}
}

func TestMiddleware_DoesNotAppendBotTagWhenDisabled(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	emptyTag := ""
	opts := DefaultOptions()
	opts.Logger = logger
	opts.SkipLoopback = false
	opts.BotTag = &emptyTag

	h := New(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := buf.String(); strings.Contains(got, "| @BOT@") {
		t.Fatalf("did not expect bot tag in log row when disabled, got: %q", got)
	}
}

func TestMiddleware_AppendsPerRequestExtraLogTokenWhenSet(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	opts := DefaultOptions()
	opts.Logger = logger
	opts.SkipLoopback = false

	extra := " | reqid=abc123"
	h := New(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok := SetLogExtra(w, extra); !ok {
			t.Fatal("expected SetLogExtra to succeed")
		}
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := buf.String(); !strings.Contains(got, extra) {
		t.Fatalf("expected extra token in log row, got: %q", got)
	}
}

func TestMiddleware_UsesDifferentPerRequestExtraValues(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	opts := DefaultOptions()
	opts.Logger = logger
	opts.SkipLoopback = false

	h := New(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = SetLogExtra(w, " | reqid="+r.URL.Query().Get("rid"))
		_, _ = w.Write([]byte("ok"))
	}))

	req1 := httptest.NewRequest(http.MethodGet, "http://example.com/test?rid=one", nil)
	req1.RemoteAddr = "8.8.8.8:1111"
	h.ServeHTTP(httptest.NewRecorder(), req1)

	req2 := httptest.NewRequest(http.MethodGet, "http://example.com/test?rid=two", nil)
	req2.RemoteAddr = "8.8.8.8:2222"
	h.ServeHTTP(httptest.NewRecorder(), req2)

	got := buf.String()
	if !strings.Contains(got, "reqid=one") || !strings.Contains(got, "reqid=two") {
		t.Fatalf("expected both per-request values in logs, got: %q", got)
	}
}
