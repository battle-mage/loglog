// loglog/loglog.go
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
	"sync"
	"time"
)

type UAQueueFn func(ua, ip string)

// BlacklistFn returns true if path should be dropped.
type BlacklistFn func(path string) bool

// TimingThresholds color rules:
//   - <= GreenMax  => green
//   - <= YellowMax => yellow (and > GreenMax)
//   - >  YellowMax => red
type TimingThresholds struct {
	GreenMax  time.Duration
	YellowMax time.Duration
}

type Options struct {
	// Blacklisting:
	// If Blacklist is set, it is used (fast compiled matcher).
	// Else if IsBlacklisted is set, it is used.
	// Else the library uses its compiled default blacklist.
	Blacklist     *Matcher
	IsBlacklisted BlacklistFn

	QueueUA UAQueueFn

	// If true, attempts to "silently" drop blacklisted requests:
	// 1) Hijack+Close when possible (HTTP/1.x)
	// 2) Otherwise panic(http.ErrAbortHandler) (no HTTP response written)
	DropSilently bool

	// If true, loopback clients are not logged/queued/blocked.
	SkipLoopback bool

	// Colors (ANSI):
	EnableColors bool

	// If true, include "DROPPED" in red for dropped connections (when EnableColors).
	ColorDropped bool

	// If true, colorize timing values based on Thresholds (when EnableColors).
	TimingColors bool
	Thresholds   TimingThresholds

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
			if opts.SkipLoopback && isLoopbackIP(clientIP) {
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

			blacklisted := false
			if opts.Blacklist != nil {
				blacklisted = opts.Blacklist.Match(path)
			} else if opts.IsBlacklisted != nil {
				blacklisted = opts.IsBlacklisted(path)
			}

			if blacklisted {
				// Keep IP, add DROPPED token (optionally red).
				opts.Logger.Printf("%s | %s | %s %s | ref: %s | orig: %s | rHost: %s | UA: %s",
					r.RemoteAddr,
					droppedWord(&opts),
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

				// Non-silent fallback if DropSilently is false.
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

			opts.Logger.Printf("%s | %s | %s | UA: %s | ref: %s | orig: %s | rHost: %s | status: %d | bytes: %s | S: %s | C: %s",
				r.RemoteAddr,
				r.Method,
				r.URL.String(),
				ua,
				referer,
				origin,
				r.Host,
				status,
				formatBytes(ww.bytes),
				colorDuration(&opts, ttfb),
				colorDuration(&opts, total),
			)
		})
	}
}

// NewChi is identical signature for chi (r.Use(loglog.NewChi(...))).
func NewChi(opts Options) func(http.Handler) http.Handler { return New(opts) }

/* ---------------- Optimized blacklist matcher ---------------- */

type Matcher struct {
	prefix *prefixTrie
	ac     *ahoCorasick
}

func NewMatcher(startsWith, contains []string) *Matcher {
	return &Matcher{
		prefix: newPrefixTrie(startsWith),
		ac:     newAhoCorasick(contains),
	}
}

func (m *Matcher) Match(path string) bool {
	if m == nil {
		return false
	}
	if m.prefix != nil && m.prefix.Match(path) {
		return true
	}
	if m.ac != nil && m.ac.Match(path) {
		return true
	}
	return false
}

var defaultStartsWith = []string{
	"/admin",
	"/login",
	"/phpmyadmin",
	"/config",
	"/setup",
	"/wp-admin",
	"/cgi-bin",
	"/sbin/init",
	"/.env",
}

var defaultContains = []string{
	".asp",
	".rsp",
	"eval-stdin.php",
	"setup-config.php",
	"app_dev.php",
	"ssh-config",
	"wp-login.php",
	"xml-rpc",
	"sslvpnlogin",
	"formJsonAjaxReq",
	"xmlrpc",
	".git",
	"developmentserver",
	"wp-config",
	"xmlrpc.php",
	"bp.php",
	"manager.php",
	"file1.php",
	"eval-stdin",
}

var (
	defaultMatcherOnce sync.Once
	defaultMatcher     *Matcher
)

func getDefaultMatcher() *Matcher {
	defaultMatcherOnce.Do(func() {
		defaultMatcher = NewMatcher(defaultStartsWith, defaultContains)
	})
	return defaultMatcher
}

/* ---------------- prefix trie (HasPrefix) ---------------- */

type prefixTrie struct {
	next map[byte]*prefixTrie
	end  bool
}

func newPrefixTrie(prefixes []string) *prefixTrie {
	if len(prefixes) == 0 {
		return nil
	}
	root := &prefixTrie{next: make(map[byte]*prefixTrie)}
	for _, p := range prefixes {
		if p == "" {
			continue
		}
		n := root
		for i := 0; i < len(p); i++ {
			b := p[i]
			child := n.next[b]
			if child == nil {
				child = &prefixTrie{}
				n.next[b] = child
			}
			if child.next == nil && i < len(p)-1 {
				child.next = make(map[byte]*prefixTrie)
			}
			n = child
		}
		n.end = true
	}
	return root
}

func (t *prefixTrie) Match(s string) bool {
	if t == nil {
		return false
	}
	n := t
	for i := 0; i < len(s); i++ {
		if n.end {
			return true
		}
		child := n.next[s[i]]
		if child == nil {
			return false
		}
		n = child
	}
	return n.end
}

/* ---------------- Aho–Corasick (Contains any) ---------------- */

type acNode struct {
	next map[byte]*acNode
	fail *acNode
	out  bool
}

type ahoCorasick struct {
	root *acNode
}

func newAhoCorasick(patterns []string) *ahoCorasick {
	if len(patterns) == 0 {
		return nil
	}
	root := &acNode{next: make(map[byte]*acNode)}

	// Build trie
	for _, p := range patterns {
		if p == "" {
			continue
		}
		n := root
		for i := 0; i < len(p); i++ {
			b := p[i]
			if n.next == nil {
				n.next = make(map[byte]*acNode)
			}
			child := n.next[b]
			if child == nil {
				child = &acNode{}
				n.next[b] = child
			}
			if child.next == nil && i < len(p)-1 {
				child.next = make(map[byte]*acNode)
			}
			n = child
		}
		n.out = true
	}

	// Build failure links (BFS)
	queue := make([]*acNode, 0, 64)
	for _, child := range root.next {
		child.fail = root
		queue = append(queue, child)
	}

	for qi := 0; qi < len(queue); qi++ {
		cur := queue[qi]
		for b, nxt := range cur.next {
			f := cur.fail
			for f != nil && f != root && f.next[b] == nil {
				f = f.fail
			}
			if f == nil || f.next[b] == nil {
				nxt.fail = root
			} else {
				nxt.fail = f.next[b]
			}
			if nxt.fail != nil && nxt.fail.out {
				nxt.out = true
			}
			queue = append(queue, nxt)
		}
	}

	return &ahoCorasick{root: root}
}

func (a *ahoCorasick) Match(s string) bool {
	if a == nil || a.root == nil {
		return false
	}
	n := a.root
	for i := 0; i < len(s); i++ {
		b := s[i]
		for n != a.root && n.next[b] == nil {
			n = n.fail
		}
		if nxt := n.next[b]; nxt != nil {
			n = nxt
		}
		if n.out {
			return true
		}
	}
	return false
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
	// If caller didn't set a blacklist function or matcher, use compiled default matcher.
	if opts.Blacklist == nil && opts.IsBlacklisted == nil {
		opts.Blacklist = getDefaultMatcher()
	}
}

func droppedWord(opts *Options) string {
	word := "DROPPED"
	if !opts.EnableColors || !opts.ColorDropped {
		return word
	}
	return ansiRed(word) + ansiReset()
}

func colorDuration(opts *Options, d time.Duration) string {
	// Keep behavior: if no write happened, show -1ms uncolored.
	ms := d.Milliseconds()
	s := fmt.Sprintf("%dms", ms)

	if !opts.EnableColors || !opts.TimingColors {
		return s
	}
	if d < 0 {
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

func formatBytes(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%d B", n)
	}

	units := []string{"kB", "MB", "GB", "TB", "PB", "EB"}
	v := float64(n)
	for i, unit := range units {
		v /= 1000
		if v < 1000 || i == len(units)-1 {
			return fmt.Sprintf("%.1f %s", v, unit)
		}
	}

	return fmt.Sprintf("%d B", n)
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

// Preserve optional interfaces.
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
