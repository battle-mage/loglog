package loglog

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type UAQueueFn func(ua, ip string)

// BlacklistFn returns true if path should be dropped.
type BlacklistFn func(path string) bool

type TimingThresholds struct {
	// <= GreenMax => green
	GreenMax time.Duration
	// <= YellowMax => yellow (and > GreenMax)
	YellowMax time.Duration
	// > YellowMax => red
}

type Options struct {
	IsBlacklisted BlacklistFn
	QueueUA       UAQueueFn

	// If true, attempts to "silently" drop blacklisted requests:
	// 1) Hijack+Close when possible (HTTP/1.x)
	// 2) Otherwise panic(http.ErrAbortHandler) (no HTTP response written)
	DropSilently bool

	// If true, loopback clients are not logged/queued/blocked.
	// (matches your original behavior)
	SkipLoopback bool

	// Colors
	EnableColors  bool
	ColorDropped  bool
	TimingColors  bool
	Thresholds    TimingThresholds

	// Logger (defaults to log.Default()).
	Logger *log.Logger
}

func DefaultOptions() Options {
	return Options{
		DropSilently: true,
		SkipLoopback: true,
		EnableColors: isTerminal(os.Stderr),
		ColorDropped: true,
		TimingColors: true,
		Thresholds: TimingThresholds{
			GreenMax:  100 * time.Millisecond,
			YellowMax: 1000 * time.Millisecond,
		},
		Logger: log.Default(),
	}
}

// New returns standard net/http middleware: func(http.Handler) http.Handler
func New(opts Options) func(http.Handler) http.Handler {
	applyDefaults(&opts)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			clientIP := remoteIP(r.RemoteAddr)
			isLoopback := opts.SkipLoopback && isLoopbackIP(clientIP)

			// If skipping loopback, just pass-through.
			if isLoopback {
				next.ServeHTTP(w, r)
				return
			}

			ua := r.UserAgent()
			path := r.URL.Path
			referer := r.Referer()
			origin := r.Header.Get("Origin")

			if opts.QueueUA != nil {
				opts.QueueUA(ua, clientIP)
			}

			ww := newTimingWriter(w)

			// Drop if blacklisted
			if opts.IsBlacklisted != nil && opts.IsBlacklisted(path) {
				opts.Logger.Printf("%s %s %s | ref: %s | orig: %s | rHost: %s | UA: %s",
					droppedPrefix(&opts),
					r.Method,
					path,
					referer,
					origin,
					r.Host,
					ua,
				)

				if opts.DropSilently && tryHijackClose(ww) {
					return
				}
				if opts.DropSilently {
					// Abort without writing any response.
					panic(http.ErrAbortHandler)
				}

				// Non-silent fallback (if user disabled silent dropping)
				http.NotFound(ww, r)
				return
			}

			next.ServeHTTP(ww, r)

			ttfb := ww.timeToFirstWrite(start)
			total := time.Since(start)

			status := ww.status
			if status == 0 {
				status = http.StatusOK
			}

			opts.Logger.Printf("%s | %s | %s | UA: %s | ref: %s | orig: %s | rHost: %s | status: %d | bytes: %d | S: %s | C: %s",
				r.RemoteAddr,
				r.Method,
				r.URL.String(),
				ua,
				referer,
				origin,
				r.Host,
				status,
				ww.bytes,
				colorDuration(&opts, ttfb),
				colorDuration(&opts, total),
			)
		})
	}
}

// NewChi is the same middleware signature as chi expects, provided as a separate entry point.
func NewChi(opts Options) func(http.Handler) http.Handler {
	return New(opts)
}

/* ---------------- internals ---------------- */

func applyDefaults(opts *Options) {
	def := DefaultOptions()
	if opts.Logger == nil {
		opts.Logger = def.Logger
	}
	if opts.Thresholds.GreenMax == 0 && opts.Thresholds.YellowMax == 0 {
		opts.Thresholds = def.Thresholds
	}
	// If user didn't set EnableColors explicitly, keep whatever they set.
	// But if they left it false (zero value), that's a valid choice.
	// So we only auto-enable colors if EnableColors is true already or default says terminal.
	if !opts.EnableColors {
		// leave as-is (explicit off)
	} else {
		// keep on
	}
	// If caller didn't fill any color flags but wants defaults, they should call DefaultOptions().
	// To keep behavior predictable, do not force-enable individual flags here.
}

func droppedPrefix(opts *Options) string {
	word := "DROPPED"
	if !opts.EnableColors || !opts.ColorDropped {
		return word
	}
	return ansiRed(word) + ansiReset()
}

func colorDuration(opts *Options, d time.Duration) string {
	s := fmt.Sprintf("%dms", d.Milliseconds())
	if !opts.EnableColors || !opts.TimingColors {
		return s
	}

	if d <= opts.Thresholds.GreenMax {
		return ansiGreen(s) + ansiReset()
	}
	if d <= opts.Thresholds.YellowMax {
		return ansiYellow(s) + ansiReset()
	}
	return ansiRed(s) + ansiReset()
}

func remoteIP(remoteAddr string) string {
	// Handles "ip:port" and "[ipv6]:port"
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(remoteAddr, "[]")
}

func isLoopbackIP(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLoopback()
}

type timingWriter struct {
	http.ResponseWriter
	status       int
	bytes        int64
	firstWriteAt time.Time
}

func newTimingWriter(w http.ResponseWriter) *timingWriter {
	return &timingWriter{ResponseWriter: w}
}

func (tw *timingWriter) WriteHeader(code int) {
	if tw.firstWriteAt.IsZero() {
		tw.firstWriteAt = time.Now()
	}
	tw.status = code
	tw.ResponseWriter.WriteHeader(code)
}

func (tw *timingWriter) Write(p []byte) (int, error) {
	if tw.firstWriteAt.IsZero() {
		tw.firstWriteAt = time.Now()
	}
	if tw.status == 0 {
		tw.status = http.StatusOK
	}
	n, err := tw.ResponseWriter.Write(p)
	tw.bytes += int64(n)
	return n, err
}

// Support common optional interfaces so we don't break HTTP/2, websockets, etc.
func (tw *timingWriter) Flush() {
	if f, ok := tw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (tw *timingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := tw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijacker not supported")
	}
	return h.Hijack()
}
func (tw *timingWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := tw.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}
func (tw *timingWriter) ReadFrom(r io.Reader) (int64, error) {
	// Optional optimization for io.Copy; keep timing consistent.
	if rf, ok := tw.ResponseWriter.(io.ReaderFrom); ok {
		if tw.firstWriteAt.IsZero() {
			tw.firstWriteAt = time.Now()
		}
		if tw.status == 0 {
			tw.status = http.StatusOK
		}
		n, err := rf.ReadFrom(r)
		tw.bytes += n
		return n, err
	}
	return io.Copy(tw.ResponseWriter, r)
}

func (tw *timingWriter) timeToFirstWrite(start time.Time) time.Duration {
	if tw.firstWriteAt.IsZero() {
		return -1 * time.Millisecond
	}
	return tw.firstWriteAt.Sub(start)
}

func tryHijackClose(w http.ResponseWriter) bool {
	h, ok := w.(http.Hijacker)
	if !ok {
		return false
	}
	conn, _, err := h.Hijack()
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func isTerminal(f *os.File) bool {
	// Minimal check: if it's a char device, treat as terminal-ish.
	// (Better detection can be added if you want; this avoids extra deps.)
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func ansiRed(s string) string    { return "\x1b[31m" + s }
func ansiGreen(s string) string  { return "\x1b[32m" + s }
func ansiYellow(s string) string { return "\x1b[33m" + s }
func ansiReset() string          { return "\x1b[0m" }
