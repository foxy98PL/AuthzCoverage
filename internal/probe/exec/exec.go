// Package exec sends probe requests. It is the only package allowed to use
// net/http. Every request is safety-checked, dials the checked IP (pinned),
// follows no redirects, and is rate limited, budgeted and audited.
package exec

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"authzcov/internal/probe/credentials"
	"authzcov/internal/probe/items"
	"authzcov/internal/probe/safety"
	"authzcov/internal/redact"
)

// Defaults (acceptance criteria).
const (
	DefaultRate    = 5.0
	DefaultBudget  = 500
	DefaultBreaker = 5
	maxBody        = 1 << 20
)

// Outcomes of one item.
const (
	OutcomeSent    = "sent"
	OutcomeSkipped = "skipped"
	OutcomeUnknown = "unknown" // never counts as covered
)

// Run-stopping errors.
var (
	ErrBudget  = errors.New("probe: request budget exhausted")
	ErrBreaker = errors.New("probe: circuit breaker open (consecutive 5xx or transport failures)")
	ErrRefused = errors.New("probe: target refused by safety policy")
	ErrAudit   = errors.New("probe: audit log write failed")
)

// Config configures an Executor.
type Config struct {
	BaseURL  string // confirmed target base URL
	Checker  *safety.Checker
	Provider *credentials.Provider // nil: only anonymous items run
	Audit    io.Writer             // JSONL, never receives credentials
	RunID    string
	Version  string

	Rate    float64 // requests per second; <=0 -> DefaultRate
	Budget  int     // max requests incl. logins; <=0 -> DefaultBudget
	Breaker int     // consecutive failures that stop the run; <=0 -> DefaultBreaker
	Timeout time.Duration

	rootCAs *x509.CertPool // test seam only; TLS verification is always on
}

// Result is the observed outcome of one item. It carries no headers or body.
type Result struct {
	Item     items.Item
	Outcome  string
	Status   int
	Redirect bool // a 3xx was observed and not followed
	Reason   string
}

// Executor runs probe items. It implements credentials.Doer for logins.
type Executor struct {
	cfg    Config
	base   *url.URL
	client *http.Client
	lim    *rate.Limiter

	mu     sync.Mutex // guards the counters and the audit writer
	seq    int
	used   int
	consec int
	stop   error                // run-stopping error seen inside a login
	logins map[string]*loginRec // identity -> login not yet audited
}

type decisionKey struct{}

// NewResolver returns the system resolver as a safety.Resolver.
func NewResolver() safety.Resolver { return sysResolver{} }

type sysResolver struct{}

func (sysResolver) LookupNetIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// New validates the configuration. It refuses to run when net/http debug
// logging could print headers.
func New(cfg Config) (*Executor, error) {
	if strings.Contains(os.Getenv("GODEBUG"), "http2debug") {
		return nil, errors.New("probe: refusing to run with GODEBUG http2debug set (it prints headers)")
	}
	if cfg.Checker == nil || cfg.Audit == nil {
		return nil, errors.New("probe: checker and audit writer are required")
	}
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || base.Host == "" {
		return nil, errors.New("probe: invalid base URL")
	}
	if cfg.Rate <= 0 {
		cfg.Rate = DefaultRate
	}
	if cfg.Budget <= 0 {
		cfg.Budget = DefaultBudget
	}
	if cfg.Breaker <= 0 {
		cfg.Breaker = DefaultBreaker
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	e := &Executor{cfg: cfg, base: base, logins: map[string]*loginRec{}, lim: rate.NewLimiter(rate.Limit(cfg.Rate), 1)}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           e.dialPinned,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.rootCAs},
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{}, // HTTP/1.1 only
		DisableKeepAlives:     true,                                                   // every request is re-checked and re-dialed
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: cfg.Timeout,
	}
	e.client = &http.Client{
		Transport:     tr,
		Timeout:       cfg.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return e, nil
}

// dialPinned dials only an address validated by the Decision stored in ctx.
func (e *Executor) dialPinned(ctx context.Context, network, addr string) (net.Conn, error) {
	d, ok := ctx.Value(decisionKey{}).(safety.Decision)
	if !ok || !d.Allowed {
		return nil, errors.New("probe: dial without an allowed safety decision")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), ".")) != d.Host || port != fmt.Sprint(d.Port) {
		return nil, errors.New("probe: dial target differs from the checked target")
	}
	var dialer net.Dialer
	for _, ip := range d.Addrs {
		cd := e.cfg.Checker.CheckAddr(d, ip)
		if !cd.Allowed {
			continue
		}
		c, derr := dialer.DialContext(ctx, network, netip.AddrPortFrom(ip, d.Port).String())
		if derr == nil {
			return c, nil
		}
	}
	return nil, errors.New("probe: no checked address reachable")
}

// Run sends each executable item in order. It stops, returning the results so
// far, on budget exhaustion, breaker trip, safety refusal or cancellation.
func (e *Executor) Run(ctx context.Context, its []items.Item) ([]Result, error) {
	var out []Result
	for _, it := range its {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if !it.Executable {
			out = append(out, Result{Item: it, Outcome: OutcomeSkipped, Reason: it.Reason})
			continue
		}
		var cred *credentials.Credential
		if it.AttackerIdentity != "" {
			c, res, err := e.credential(ctx, it)
			if err != nil {
				return out, err
			}
			if res != nil {
				out = append(out, *res)
				continue
			}
			cred = &c
		}
		resp, err := e.send(ctx, it, cred)
		if err != nil {
			if errors.Is(err, errTransport) {
				out = append(out, Result{Item: it, Outcome: OutcomeUnknown, Reason: reasonOf(err)})
				if errors.Is(err, ErrBreaker) {
					return out, ErrBreaker
				}
				continue
			}
			return out, err
		}
		out = append(out, Result{Item: it, Outcome: OutcomeSent, Status: resp.status, Redirect: resp.status >= 300 && resp.status < 400})
		if e.tripped() {
			return out, ErrBreaker
		}
	}
	return out, nil
}

// loginRec is one login performed by Do, waiting to be audited per identity.
type loginRec struct{ status int }

type identityKey struct{}

// takeLogin returns and clears the identity's unaudited login, if any.
func (e *Executor) takeLogin(id string) *loginRec {
	e.mu.Lock()
	defer e.mu.Unlock()
	r := e.logins[id]
	delete(e.logins, id)
	return r
}

func (e *Executor) tripped() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.consec >= e.cfg.Breaker
}

// credential returns the identity's credential, or a Result when the item
// cannot be sent (login failed, no recipe). A non-nil error stops the run.
func (e *Executor) credential(ctx context.Context, it items.Item) (credentials.Credential, *Result, error) {
	unknown := func(reason string) (credentials.Credential, *Result, error) {
		return credentials.Credential{}, &Result{Item: it, Outcome: OutcomeUnknown, Reason: reason}, nil
	}
	if e.cfg.Provider == nil {
		return unknown("no_credential")
	}
	lctx := context.WithValue(ctx, identityKey{}, it.AttackerIdentity)
	cred, err := e.cfg.Provider.For(lctx, it.AttackerIdentity, e)
	lr := e.takeLogin(it.AttackerIdentity) // non-nil only when a login happened just now
	switch {
	case err == nil:
		if lr != nil {
			if aerr := e.auditLine(map[string]any{"event": "login", "identity": it.AttackerIdentity,
				"msg": fmt.Sprintf("login identity=%s status=%d fp=%s", it.AttackerIdentity, lr.status, redact.Fingerprint(cred.Token.Expose()))}); aerr != nil {
				return cred, nil, aerr
			}
		}
		return cred, nil, nil
	case errors.Is(err, credentials.ErrNoRecipe):
		return unknown("no_credential")
	case ctx.Err() != nil:
		return cred, nil, ctx.Err()
	}
	e.mu.Lock()
	stop := e.stop
	e.mu.Unlock()
	if stop != nil {
		return cred, nil, stop
	}
	var le *credentials.LoginError
	if errors.As(err, &le) {
		if lr != nil {
			if aerr := e.auditLine(map[string]any{"event": "login", "identity": it.AttackerIdentity, "reason": le.Reason, "msg": le.Error()}); aerr != nil {
				return cred, nil, aerr
			}
		}
		if e.tripped() {
			return cred, nil, ErrBreaker
		}
		return unknown("login_failed")
	}
	return unknown("login_failed")
}

var errTransport = errors.New("transport")

type transportErr struct {
	reason string
	trip   bool
}

func (t *transportErr) Error() string { return "probe: request failed: " + t.reason }
func (t *transportErr) Is(target error) bool {
	return target == errTransport || (t.trip && target == ErrBreaker)
}

func reasonOf(err error) string {
	var te *transportErr
	if errors.As(err, &te) {
		return te.reason
	}
	return "transport"
}

type sent struct {
	status int
	header http.Header
	body   []byte
}

// send performs one request through the shared pipeline. It returns a
// run-stopping error, a *transportErr, or a response.
func (e *Executor) send(ctx context.Context, it items.Item, cred *credentials.Credential) (*sent, error) {
	return e.roundTrip(ctx, it.Method, it.Path, nil, nil, cred, it, false)
}

func (e *Executor) roundTrip(ctx context.Context, method, path string, hdr map[string]string, body io.Reader,
	cred *credentials.Credential, it items.Item, keepBody bool) (*sent, error) {
	refuse := func(reason string) (*sent, error) {
		if aerr := e.auditLine(map[string]any{"event": "refused", "probe_id": it.ProbeID, "reason": reason}); aerr != nil {
			return nil, aerr
		}
		return nil, fmt.Errorf("%w: %s", ErrRefused, reason)
	}
	if !validPath(path) {
		return refuse("bad_path")
	}
	target := e.target(path)
	d := e.cfg.Checker.Check(ctx, target)
	if !d.Allowed {
		return refuse(string(d.Reason))
	}
	if d.Host != e.baseHost() || d.Port != e.basePort() {
		return refuse("target_differs_from_confirmed_base")
	}
	if err := e.lim.Wait(ctx); err != nil {
		return nil, err
	}
	e.mu.Lock()
	if e.used >= e.cfg.Budget {
		e.mu.Unlock()
		return nil, ErrBudget
	}
	e.used++
	e.seq++
	seq := e.seq
	e.mu.Unlock()

	rec := map[string]any{"seq": seq, "probe_id": it.ProbeID, "method": method, "path_fp": redact.Fingerprint(stripQuery(path)),
		"identity": it.AttackerIdentity, "expect": it.Expect}
	if err := e.auditLine(merge(rec, map[string]any{"event": "intent"})); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(context.WithValue(ctx, decisionKey{}, d), method, target, body)
	if err != nil {
		return nil, &transportErr{reason: "bad_request"}
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if cred != nil {
		cred.SetOn(func(n, v string) { req.Header.Set(n, v) })
	}
	req.Header.Set("User-Agent", "authzcov/"+e.cfg.Version)
	req.Header.Set("X-Authzcov-Run", e.cfg.RunID)

	start := time.Now()
	resp, err := e.client.Do(req)
	ms := time.Since(start).Milliseconds()
	if err != nil {
		reason := "transport"
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			reason = "timeout"
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		e.mu.Lock()
		e.consec++
		trip := e.consec >= e.cfg.Breaker
		e.mu.Unlock()
		if aerr := e.auditLine(merge(rec, map[string]any{"event": "result", "reason": reason, "duration_ms": ms})); aerr != nil {
			return nil, aerr
		}
		return nil, &transportErr{reason: reason, trip: trip}
	}
	defer resp.Body.Close()
	limit := int64(maxBody)
	if keepBody {
		limit = credentials.MaxLoginBody + 1
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	e.mu.Lock()
	if resp.StatusCode >= 500 {
		e.consec++
	} else {
		e.consec = 0
	}
	e.mu.Unlock()
	if !keepBody {
		b = nil
	}
	if err := e.auditLine(merge(rec, map[string]any{"event": "result", "status": resp.StatusCode, "duration_ms": ms})); err != nil {
		return nil, err
	}
	return &sent{status: resp.StatusCode, header: resp.Header, body: b}, nil
}

// Do sends a login request through the same pipeline (credentials.Doer).
func (e *Executor) Do(ctx context.Context, req credentials.LoginRequest) (credentials.LoginResponse, error) {
	it := items.Item{ProbeID: "login", Method: req.Method, Path: req.Path}
	var body io.Reader
	if s := req.Body.Expose(); s != "" {
		body = strings.NewReader(s)
	}
	id, _ := ctx.Value(identityKey{}).(string)
	if id != "" {
		e.mu.Lock()
		e.logins[id] = &loginRec{}
		e.mu.Unlock()
	}
	r, err := e.roundTrip(ctx, req.Method, req.Path, req.Header, body, nil, it, true)
	if err != nil {
		if errors.Is(err, ErrBudget) || errors.Is(err, ErrRefused) || errors.Is(err, ErrAudit) {
			e.mu.Lock()
			e.stop = err
			e.mu.Unlock()
		}
		return credentials.LoginResponse{}, err
	}
	e.mu.Lock()
	if lr := e.logins[id]; lr != nil {
		lr.status = r.status
	}
	e.mu.Unlock()
	return credentials.LoginResponse{Status: r.status, Header: r.header, Body: io.NopCloser(strings.NewReader(string(r.body)))}, nil
}

// target joins the confirmed base URL and an item path, unmodified, using the
// scheme and host:port of the base.
func (e *Executor) target(path string) string {
	b := *e.base
	return b.Scheme + "://" + b.Host + strings.TrimSuffix(b.EscapedPath(), "/") + path
}

// validPath accepts only an origin-form path: it must start with a single "/"
// and carry no backslash, so it cannot alter the scheme, host or port.
func validPath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.ContainsAny(p, "\\ \t\r\n")
}

func (e *Executor) baseHost() string {
	return strings.ToLower(strings.TrimSuffix(e.base.Hostname(), "."))
}

func (e *Executor) basePort() uint16 {
	if p := e.base.Port(); p != "" {
		n, _ := strconv.ParseUint(p, 10, 16)
		return uint16(n)
	}
	if e.base.Scheme == "http" {
		return 80
	}
	return 443
}

func stripQuery(p string) string {
	s, _, _ := strings.Cut(p, "?")
	return s
}

func merge(a, b map[string]any) map[string]any {
	out := make(map[string]any, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// auditLine writes one JSONL record. A failed write is fatal for the run
// (fail closed): it is remembered in e.stop and returned wrapped in ErrAudit.
func (e *Executor) auditLine(m map[string]any) error {
	m["run_id"] = e.cfg.RunID
	b, err := json.Marshal(m)
	e.mu.Lock()
	defer e.mu.Unlock()
	if err == nil {
		_, err = e.cfg.Audit.Write(append(b, '\n'))
	}
	if err != nil {
		aerr := fmt.Errorf("%w: %w", ErrAudit, err)
		if e.stop == nil {
			e.stop = aerr
		}
		return aerr
	}
	return nil
}
