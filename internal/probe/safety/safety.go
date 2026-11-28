// Package safety decides whether a probe request may be sent to a target.
// It is pure policy: it imports neither net nor net/http, resolution goes
// through an injected Resolver, and every unknown or ambiguous input is
// refused (fail-closed). Check has no error return so an ignored error can
// never be read as "allowed".
package safety

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Reason is a stable machine-readable code.
type Reason string

// Decision reasons. They never contain URL paths, queries or userinfo.
const (
	OKLoopback     Reason = "ok_loopback"
	OKPrivate      Reason = "ok_private"
	OKAllowlisted  Reason = "ok_allowlisted"
	ReasonParse    Reason = "parse_error"
	ReasonScheme   Reason = "scheme"
	ReasonUserinfo Reason = "userinfo"
	ReasonNonASCII Reason = "non_ascii"
	ReasonBadHost  Reason = "bad_host"
	ReasonBadPort  Reason = "bad_port"
	ReasonAmbigIP  Reason = "ambiguous_ip"
	ReasonZone     Reason = "zone"
	ReasonMetadata Reason = "metadata"
	ReasonBlocked  Reason = "blocked_address"
	ReasonResolve  Reason = "resolve_failed"
	ReasonNotAllow Reason = "not_allowlisted"
	ReasonNoConfrm Reason = "no_confirm"
	ReasonPublic   Reason = "public_needs_allow_public"
	ReasonMismatch Reason = "addr_mismatch"
	ReasonRefused  Reason = "refused"
)

// Resolver resolves a host to addresses. Implemented in the exec layer.
type Resolver interface {
	LookupNetIP(ctx context.Context, host string) ([]netip.Addr, error)
}

// Policy holds the user-supplied allowlist and confirmations.
type Policy struct {
	AllowHosts     []string // host, host:port or *.suffix
	ConfirmTargets []string // host or host:port, exact
	AllowPublic    bool
}

// Decision is the outcome of a check. The zero value is a refusal.
type Decision struct {
	Allowed bool
	Reason  Reason
	Host    string
	Port    uint16
	Addrs   []netip.Addr
}

// Checker evaluates targets against a Policy.
type Checker struct {
	allow   []entry
	confirm []entry
	public  bool
	res     Resolver
}

type entry struct {
	host     string
	port     uint16 // 0 = any
	wildcard bool
}

// New validates the policy. An error means a usage error (exit 2).
func New(p Policy, r Resolver) (*Checker, error) {
	if r == nil {
		return nil, errors.New("safety: nil resolver")
	}
	c := &Checker{public: p.AllowPublic, res: r}
	for _, s := range p.AllowHosts {
		e, err := parseEntry(s, true)
		if err != nil {
			return nil, fmt.Errorf("probe.allow_hosts entry %q: %w", s, err)
		}
		c.allow = append(c.allow, e)
	}
	for _, s := range p.ConfirmTargets {
		e, err := parseEntry(s, false)
		if err != nil {
			return nil, fmt.Errorf("--confirm-target %q: %w", s, err)
		}
		c.confirm = append(c.confirm, e)
	}
	return c, nil
}

func parseEntry(s string, wildOK bool) (entry, error) {
	var e entry
	if s == "" || strings.ContainsAny(s, "/@?#") {
		return e, errors.New("invalid entry")
	}
	hostPart, portPart := s, ""
	if strings.HasPrefix(s, "[") {
		i := strings.Index(s, "]")
		if i < 0 {
			return e, errors.New("invalid entry")
		}
		hostPart = s[:i+1]
		rest := s[i+1:]
		if rest != "" {
			if rest[0] != ':' {
				return e, errors.New("invalid entry")
			}
			portPart = rest[1:]
			if portPart == "" {
				return e, errors.New("invalid port")
			}
		}
	} else if i := strings.LastIndex(s, ":"); i >= 0 {
		hostPart, portPart = s[:i], s[i+1:]
		if portPart == "" || strings.Contains(hostPart, ":") {
			return e, errors.New("invalid entry")
		}
	}
	if portPart != "" {
		p, ok := parsePort(portPart)
		if !ok {
			return e, errors.New("invalid port")
		}
		e.port = p
	}
	if strings.HasPrefix(hostPart, "*.") {
		if !wildOK {
			return e, errors.New("wildcard not allowed")
		}
		suffix, kind, why := normalizeHost(hostPart[2:])
		if why != "" || kind != kindName || strings.Count(suffix, ".") < 1 {
			return e, errors.New("wildcard needs a name suffix of at least two labels")
		}
		e.host, e.wildcard = suffix, true
		return e, nil
	}
	h, _, why := normalizeHost(hostPart)
	if why != "" {
		return e, fmt.Errorf("invalid host (%s)", why)
	}
	e.host = h
	return e, nil
}

func (e entry) matches(host string, port uint16) bool {
	if e.port != 0 && e.port != port {
		return false
	}
	if e.wildcard {
		return len(host) > len(e.host)+1 && strings.HasSuffix(host, "."+e.host)
	}
	return e.host == host
}

func anyMatch(es []entry, host string, port uint16) bool {
	for _, e := range es {
		if e.matches(host, port) {
			return true
		}
	}
	return false
}

func parsePort(s string) (uint16, bool) {
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, false
	}
	return uint16(n), true
}

type hostKind int

const (
	kindName hostKind = iota
	kindIP
)

// normalizeHost canonicalises a host (no port). A non-empty Reason return
// means refusal. IPv6 literals are expected in brackets.
func normalizeHost(h string) (string, hostKind, Reason) {
	if h == "" {
		return "", 0, ReasonBadHost
	}
	for i := 0; i < len(h); i++ {
		if h[i] >= 0x80 {
			return "", 0, ReasonNonASCII
		}
	}
	if strings.HasPrefix(h, "[") {
		if !strings.HasSuffix(h, "]") {
			return "", 0, ReasonBadHost
		}
		inner := h[1 : len(h)-1]
		if strings.Contains(inner, "%") {
			return "", 0, ReasonZone
		}
		a, err := netip.ParseAddr(inner)
		if err != nil || !a.Is6() {
			return "", 0, ReasonBadHost
		}
		return a.String(), kindIP, ""
	}
	if strings.Contains(h, "%") {
		return "", 0, ReasonBadHost
	}
	h = strings.ToLower(h)
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return "", 0, ReasonBadHost
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return "", 0, ReasonBadHost
		}
		for i := 0; i < len(l); i++ {
			ch := l[i]
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return "", 0, ReasonBadHost
			}
		}
	}
	if a, err := netip.ParseAddr(h); err == nil {
		if a.Is4() {
			return a.String(), kindIP, ""
		}
		return "", 0, ReasonBadHost
	}
	if looksNumeric(labels[len(labels)-1]) {
		return "", 0, ReasonAmbigIP
	}
	return h, kindName, ""
}

// looksNumeric reports whether a last label would be read as a number by
// inet_aton (decimal, octal or 0x hex).
func looksNumeric(l string) bool {
	if strings.HasPrefix(l, "0x") {
		return true
	}
	for i := 0; i < len(l); i++ {
		if l[i] < '0' || l[i] > '9' {
			return false
		}
	}
	return true
}

type class int

const (
	clsAuto   class = iota // loopback / private
	clsNonPub              // CGNAT
	clsPublic
	clsRefuse
)

var (
	cgnat      = netip.MustParsePrefix("100.64.0.0/10")
	nat64      = netip.MustParsePrefix("64:ff9b::/96")
	ec2v6      = netip.MustParseAddr("fd00:ec2::254")
	alibaba    = netip.MustParseAddr("100.100.100.200")
	zeroNet    = netip.MustParsePrefix("0.0.0.0/8")
	bcast      = netip.MustParseAddr("255.255.255.255")
	loopback6  = netip.MustParseAddr("::1")
	unspec6    = netip.IPv6Unspecified()
	compat6Pfx = netip.MustParsePrefix("::/96")
)

func classify(ip netip.Addr) (class, Reason) {
	if ip.Zone() != "" {
		return clsRefuse, ReasonZone
	}
	ip = ip.Unmap()
	switch {
	case !ip.IsValid():
		return clsRefuse, ReasonBlocked
	case ip == ec2v6 || ip == alibaba:
		return clsRefuse, ReasonMetadata
	case ip.Is4() && ip.As4()[0] == 169 && ip.As4()[1] == 254:
		return clsRefuse, ReasonMetadata
	case ip.IsUnspecified() || ip == unspec6 || (ip.Is4() && zeroNet.Contains(ip)),
		ip.IsMulticast(), ip == bcast, ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(),
		ip.IsInterfaceLocalMulticast(), nat64.Contains(ip):
		return clsRefuse, ReasonBlocked
	case ip.Is6() && ip != loopback6 && compat6Pfx.Contains(ip):
		return clsRefuse, ReasonBlocked
	case ip.IsLoopback():
		return clsAuto, OKLoopback
	case ip.IsPrivate():
		return clsAuto, OKPrivate
	case cgnat.Contains(ip):
		return clsNonPub, ReasonNotAllow
	}
	return clsPublic, ReasonPublic
}

var nonProd = map[string]bool{
	"staging": true, "stage": true, "stg": true, "dev": true, "develop": true, "development": true,
	"test": true, "testing": true, "qa": true, "uat": true, "sandbox": true, "sbx": true,
	"preprod": true, "nonprod": true, "demo": true, "preview": true, "ci": true, "local": true,
}

// hasNonProdLabel checks every label except the TLD.
func hasNonProdLabel(host string) bool {
	labels := strings.Split(host, ".")
	for _, l := range labels[:len(labels)-1] {
		if nonProd[l] {
			return true
		}
		for _, part := range strings.Split(l, "-") {
			if nonProd[part] {
				return true
			}
		}
	}
	return false
}

func refuse(r Reason, host string, port uint16) Decision {
	return Decision{Reason: r, Host: host, Port: port}
}

// Check evaluates rawURL. It never follows redirects; callers must call it
// again for every hop.
func (c *Checker) Check(ctx context.Context, rawURL string) Decision {
	if strings.ContainsAny(rawURL, "\\ \t\r\n") {
		// whitespace or backslash anywhere is ambiguous across parsers
		if i := strings.Index(rawURL, "://"); i < 0 || strings.ContainsAny(authorityOf(rawURL[i+3:]), "\\ \t\r\n") {
			return refuse(ReasonBadHost, "", 0)
		}
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return refuse(ReasonParse, "", 0)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return refuse(ReasonScheme, "", 0)
	}
	if u.User != nil || strings.Contains(authorityOf(afterScheme(rawURL)), "@") {
		return refuse(ReasonUserinfo, "", 0)
	}
	hostRaw := u.Host
	portStr := u.Port()
	var hostPart string
	if portStr != "" {
		hostPart = strings.TrimSuffix(hostRaw, ":"+portStr)
	} else {
		hostPart = strings.TrimSuffix(hostRaw, ":")
	}
	host, kind, why := normalizeHost(hostPart)
	if why != "" {
		return refuse(why, "", 0)
	}
	var port uint16
	if portStr != "" {
		p, ok := parsePort(portStr)
		if !ok {
			return refuse(ReasonBadPort, host, 0)
		}
		port = p
	} else if strings.EqualFold(u.Scheme, "https") {
		port = 443
	} else {
		port = 80
	}

	var addrs []netip.Addr
	if kind == kindIP {
		a, perr := netip.ParseAddr(host)
		if perr != nil {
			return refuse(ReasonBadHost, host, port)
		}
		addrs = []netip.Addr{a}
	} else {
		addrs, err = c.res.LookupNetIP(ctx, host)
		if err != nil || len(addrs) == 0 {
			return refuse(ReasonResolve, host, port)
		}
	}

	worst := clsAuto
	reason := OKPrivate
	allLoop := true
	for _, a := range addrs {
		cl, r := classify(a)
		if cl == clsRefuse {
			return refuse(r, host, port)
		}
		if cl > worst {
			worst = cl
		}
		if r != OKLoopback {
			allLoop = false
		}
	}
	if allLoop {
		reason = OKLoopback
	}

	autoName := kind == kindIP || host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".test") || !strings.Contains(host, ".")
	if autoName && worst == clsAuto {
		return Decision{Allowed: true, Reason: reason, Host: host, Port: port, Addrs: addrs}
	}

	if !anyMatch(c.allow, host, port) {
		return refuse(ReasonNotAllow, host, port)
	}
	if !anyMatch(c.confirm, host, port) {
		return refuse(ReasonNoConfrm, host, port)
	}
	if worst == clsPublic && !c.public && (kind != kindName || !hasNonProdLabel(host)) {
		return refuse(ReasonPublic, host, port)
	}
	return Decision{Allowed: true, Reason: OKAllowlisted, Host: host, Port: port, Addrs: addrs}
}

// CheckAddr re-validates an address at dial time against a prior Decision.
// The address must be one of those Check validated and must still classify
// as acceptable (guards against DNS rebinding).
func (c *Checker) CheckAddr(d Decision, ip netip.Addr) Decision {
	out := Decision{Host: d.Host, Port: d.Port}
	if cl, r := classify(ip); cl == clsRefuse {
		out.Reason = r
		return out
	}
	if !d.Allowed {
		out.Reason = d.Reason
		if out.Reason == "" {
			out.Reason = ReasonRefused
		}
		return out
	}
	u := ip.Unmap()
	for _, a := range d.Addrs {
		if a.Unmap() == u {
			d.Addrs = []netip.Addr{ip}
			return d
		}
	}
	out.Reason = ReasonMismatch
	return out
}

func afterScheme(raw string) string {
	if i := strings.Index(raw, "://"); i >= 0 {
		return raw[i+3:]
	}
	return ""
}

// authorityOf returns the part of s before the first '/', '?' or '#'.
func authorityOf(s string) string {
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		return s[:i]
	}
	return s
}
