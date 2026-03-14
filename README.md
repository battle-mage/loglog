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

Both destinations are independent and can be enabled together.

You can override config values via `Options`:
- `LogFile *string`
- `LogToConsole *bool`

- `CompactTitles bool`: use compact field labels in log rows (`orig`→`o`, `rHost`→`h`, `bytes`→`b`, `ref`→`r`, `status`→`s`, `UA` unchanged) and omit the space after `:` (for example `s:200`).

When these option fields are provided (non-`nil`), they take priority over `loglog.cfg`.

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
