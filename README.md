# loglog

## Simple http logger for go. Logs requests' basic information:
```
  RemoteAddr (IP + Port)
  HTTP Method
  URL Path
  Headers:
    UserAgent
    Referer
    Origin
  Host
  Status
  Response size
  Time-To-First-Byte
  Total Time
```

## Request timings colored
${\color{green}<= 100ms}$
${\color{yellow}<= 1000ms}$
${\color{red}> 1000ms}$
(configurable)


## Config-based logger destinations
If `loglog.cfg` exists in the process working directory, `loglog` reads these keys:

- `log_file` (string): path to log file. If missing or empty, file logging is disabled.
- `log_to_console` (`1`, `0`, or empty): whether to log to console (`1` enables, `0`/empty disables).
- `bot_tag` (string): tag appended to rows detected as bot traffic. Defaults to `@BOT@`. Set `bot_tag=` (empty) to disable tagging.

Both destinations are independent and can be enabled together.

You can override config values via `Options`:
- `LogFile *string`
- `LogToConsole *bool`
- `BotTag *string` (set to `""` to disable)

- `CompactTitles bool`: use compact field labels in log rows (`orig`→`o`, `rHost`→`h`, `bytes`→`b`, `ref`→`r`, `status`→`s`, `UA` unchanged) and omit the space after `:` (for example `s:200`).

When these option fields are provided (non-`nil`), they take priority over `loglog.cfg`.

## Bot traffic tagging
When enabled, bot requests get an extra token appended to each log row:

```
... | @BOT@
```

Detection is UA-based and includes major classes of crawlers such as:
- search crawlers (Googlebot, Bingbot, PetalBot, Bytespider, Applebot, etc.)
- SEO/index bots (DotBot / opensiteexplorer.org/dotbot, AhrefsBot / ahrefs.com/robot, SemrushBot, MJ12bot, etc.)
- social preview fetchers (facebookexternalhit, Twitterbot, LinkedInBot, Slackbot, Discordbot, etc.)
- AI crawlers (ClaudeBot, GPTBot, OAI-SearchBot, PerplexityBot, etc.)

## Request filtering (blocking)
Supports basic request filtering for most commonly abused paths (.env /admin etc)

## How to use:

Chi
```
  r.Use(loglog.NewChi(loglog.DefaultOptions()))
```

net/http (mux)
```
  handler := loglog.New(loglog.DefaultOptions())(mux)
```

## Example with all custom parameters
```go
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/your/module/loglog"
)

func main() {
	logger := log.New(os.Stdout, "http ", log.LstdFlags)

	matcher := loglog.NewMatcher(
		[]string{"/admin", "/private"},
		[]string{".env", "wp-login.php"},
	)

	opts := loglog.Options{
		Blacklist: matcher,
		IsBlacklisted: func(path string) bool {
			return path == "/blocked-by-fn"
		},
		QueueUA: func(ua, ip string) {
			// send ua/ip to a queue or analytics sink
		},
		DropSilently: true,
		SkipLoopback: false,
		EnableColors: true,
		ColorDropped: true,
		TimingColors: true,
		Thresholds: loglog.TimingThresholds{
			GreenMax:  50 * time.Millisecond,
			YellowMax: 500 * time.Millisecond,
		},
		Logger: logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	})

	handler := loglog.New(opts)(mux)
	_ = http.ListenAndServe(":8080", handler)
}
```
