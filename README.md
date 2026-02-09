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
