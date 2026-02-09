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
