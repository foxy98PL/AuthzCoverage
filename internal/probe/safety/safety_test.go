package safety

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, host string) ([]netip.Addr, error) {
	a, ok := f[host]
	if !ok {
		return nil, errors.New("nxdomain")
	}
	return a, nil
}

func ips(s ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(s))
	for _, x := range s {
		out = append(out, netip.MustParseAddr(x))
	}
	return out
}

type tc struct {
	name   string
	url    string
	pol    Policy
	dns    fakeResolver
	allow  bool
	reason Reason // checked when non-empty
	host   string // checked when non-empty
}

func TestCheckTable(t *testing.T) {
	al := func(h ...string) Policy { return Policy{AllowHosts: h} }
	alc := func(h, c string) Policy { return Policy{AllowHosts: []string{h}, ConfirmTargets: []string{c}} }
	pub := fakeResolver{"api.staging.corp.com": ips("52.1.1.1")}
	cases := []tc{
		{name: "01 localhost", url: "http://" + "localhost:8080/x", dns: fakeResolver{"localhost": ips("127.0.0.1")}, allow: true, reason: "ok_loopback"},
		{name: "02 127/8", url: "http://" + "127.1.2.3/", allow: true},
		{name: "03 ::1", url: "http://" + "[::1]:8080/", allow: true},
		{name: "04 10/8", url: "http://" + "10.0.0.5/", allow: true},
		{name: "05 172.31", url: "http://" + "172.31.255.255/", allow: true},
		{name: "06 172.32", url: "http://" + "172.32.0.1/", reason: "not_allowlisted"},
		{name: "07 192.168", url: "http://" + "192.168.1.10/", allow: true},
		{name: "08 ula", url: "http://" + "[fd12:3456::1]/", allow: true},
		{name: "09 mapped private", url: "http://" + "[::ffff:10.0.0.1]/", allow: true},
		{name: "10 mapped public", url: "http://" + "[::ffff:8.8.8.8]/"},
		{name: "11 decimal", url: "http://" + "2130706433/", reason: "ambiguous_ip"},
		{name: "12 hex", url: "http://" + "0x7f.1/", reason: "ambiguous_ip"},
		{name: "13 octal", url: "http://" + "017.0.0.1/", reason: "ambiguous_ip"},
		{name: "14 short", url: "http://" + "127.1/", reason: "ambiguous_ip"},
		{name: "15 zero", url: "http://" + "0.0.0.0/"},
		{name: "16 imds", url: "http://" + "169.254.169.254/latest", pol: Policy{AllowHosts: []string{"169.254.169.254"}, ConfirmTargets: []string{"169.254.169.254"}, AllowPublic: true}, reason: "metadata"},
		{name: "17 zone", url: "http://" + "[fe80::1%25eth0]/", reason: "zone"},
		{name: "18 linklocal6", url: "http://" + "[fe80::1]/"},
		{name: "19 ec2 v6", url: "http://" + "[fd00:ec2::254]/", reason: "metadata"},
		{name: "20 cgnat", url: "http://" + "100.64.1.1/"},
		{name: "21 cgnat AL+C", url: "http://" + "100.64.1.1/", pol: alc("100.64.1.1", "100.64.1.1"), allow: true},
		{name: "22 alibaba", url: "http://" + "100.100.100.200/", pol: alc("100.100.100.200", "100.100.100.200"), reason: "metadata"},
		{name: "23 app.test loop", url: "http://" + "app.test/", dns: fakeResolver{"app.test": ips("127.0.0.1")}, allow: true},
		{name: "24 app.test public", url: "http://" + "app.test/", dns: fakeResolver{"app.test": ips("93.184.216.34")}},
		{name: "25 single private", url: "http://" + "api/", dns: fakeResolver{"api": ips("10.1.1.1")}, allow: true},
		{name: "26 single public", url: "http://" + "api/", dns: fakeResolver{"api": ips("8.8.8.8")}},
		{name: "27 trailing dot", url: "http://" + "LOCALHOST./", dns: fakeResolver{"localhost": ips("127.0.0.1")}, allow: true, host: "localhost"},
		{name: "28 userinfo", url: "http://" + "user:" + "pw@localhost/", //nolint:gosec // synthetic userinfo
			dns: fakeResolver{"localhost": ips("127.0.0.1")}, reason: "userinfo"},
		{name: "29a ftp", url: "ftp://" + "localhost/", reason: "scheme"},
		{name: "29b file", url: "file:///etc/passwd", reason: "scheme"},
		{name: "29c gopher", url: "gopher://" + "localhost/", reason: "scheme"},
		{name: "30 non-ascii", url: "http://" + "bücher.staging.corp.com/", reason: "non_ascii"},
		{name: "31a empty label", url: "http://" + "a..b.test/"},
		{name: "31b port 0", url: "http://" + "localhost:0/", dns: fakeResolver{"localhost": ips("127.0.0.1")}},
		{name: "32 no confirm", url: "https://" + "api.staging.corp.com/", pol: al("api.staging.corp.com"), dns: pub, reason: "no_confirm"},
		{name: "33 confirmed", url: "https://" + "api.staging.corp.com/", pol: alc("api.staging.corp.com", "api.staging.corp.com"), dns: pub, allow: true},
		{name: "34 wrong confirm", url: "https://" + "api.staging.corp.com/", pol: alc("api.staging.corp.com", "other.staging.corp.com"), dns: pub},
		{name: "35a wildcard", url: "https://" + "x.qa.corp.com/", pol: alc("*.qa.corp.com", "x.qa.corp.com"), dns: fakeResolver{"x.qa.corp.com": ips("52.1.1.1")}, allow: true},
		{name: "35b apex", url: "https://" + "qa.corp.com/", pol: alc("*.qa.corp.com", "qa.corp.com"), dns: fakeResolver{"qa.corp.com": ips("52.1.1.1")}, reason: "not_allowlisted"},
		{name: "36a prod no AP", url: "https://" + "prod.corp.com:8443/", pol: alc("prod.corp.com:8443", "prod.corp.com"), dns: fakeResolver{"prod.corp.com": ips("52.1.1.1")}, reason: "public_needs_allow_public"},
		{name: "36b prod AP", url: "https://" + "prod.corp.com:8443/", pol: Policy{AllowHosts: []string{"prod.corp.com:8443"}, ConfirmTargets: []string{"prod.corp.com"}, AllowPublic: true}, dns: fakeResolver{"prod.corp.com": ips("52.1.1.1")}, allow: true},
		{name: "37 port mismatch", url: "https://" + "prod.corp.com/", pol: alc("prod.corp.com:8443", "prod.corp.com"), dns: fakeResolver{"prod.corp.com": ips("52.1.1.1")}, reason: "not_allowlisted"},
		{name: "38a private AL+C", url: "https://" + "api.corp.com/", pol: alc("api.corp.com", "api.corp.com"), dns: fakeResolver{"api.corp.com": ips("10.2.3.4")}, allow: true},
		{name: "38b private no AL", url: "https://" + "api.corp.com/", dns: fakeResolver{"api.corp.com": ips("10.2.3.4")}, reason: "not_allowlisted"},
		{name: "39 mixed", url: "https://" + "api.corp.com/", pol: alc("api.corp.com", "api.corp.com"), dns: fakeResolver{"api.corp.com": ips("10.2.3.4", "52.1.1.1")}, reason: "public_needs_allow_public"},
		{name: "40a tld", url: "https://" + "api.dev/", pol: alc("api.dev", "api.dev"), dns: fakeResolver{"api.dev": ips("52.1.1.1")}, reason: "public_needs_allow_public"},
		{name: "40b substring", url: "https://" + "devices.corp.com/", pol: alc("devices.corp.com", "devices.corp.com"), dns: fakeResolver{"devices.corp.com": ips("52.1.1.1")}, reason: "public_needs_allow_public"},
		{name: "40c nxdomain", url: "http://" + "x.test/", reason: "resolve_failed"},
		{name: "40d empty answer", url: "http://" + "x.test/", dns: fakeResolver{"x.test": {}}, reason: "resolve_failed"},
		{name: "41 mixed with metadata", url: "http://" + "x.test/", dns: fakeResolver{"x.test": ips("127.0.0.1", "169.254.169.254")}, reason: "metadata"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ch, err := New(c.pol, c.dns)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			d := ch.Check(context.Background(), c.url)
			if d.Allowed != c.allow {
				t.Fatalf("Allowed=%v want %v (reason %q)", d.Allowed, c.allow, d.Reason)
			}
			if c.reason != "" && d.Reason != c.reason {
				t.Fatalf("Reason=%q want %q", d.Reason, c.reason)
			}
			if c.host != "" && d.Host != c.host {
				t.Fatalf("Host=%q want %q", d.Host, c.host)
			}
			if strings.Contains(string(d.Reason), "pw") || strings.Contains(string(d.Reason), "/") {
				t.Fatalf("reason leaks URL data: %q", d.Reason)
			}
		})
	}
}

func TestNewRejectsBadEntries(t *testing.T) {
	for _, e := range []string{"*", "*.com", "10.0.0.0/8", "a..b", "", "host:0", "host:99999"} {
		if _, err := New(Policy{AllowHosts: []string{e}}, fakeResolver{}); err == nil {
			t.Errorf("allow entry %q accepted", e)
		}
	}
	for _, e := range []string{"*.corp.com", "", "a..b"} {
		if _, err := New(Policy{ConfirmTargets: []string{e}}, fakeResolver{}); err == nil {
			t.Errorf("confirm entry %q accepted", e)
		}
	}
}

func TestNewNilResolver(t *testing.T) {
	if _, err := New(Policy{}, nil); err == nil {
		t.Fatal("nil resolver accepted")
	}
}

func TestCheckAddrRebinding(t *testing.T) {
	ch, _ := New(Policy{}, fakeResolver{"app.test": ips("127.0.0.1")})
	d := ch.Check(context.Background(), "http://"+"app.test/")
	if !d.Allowed {
		t.Fatalf("setup: %q", d.Reason)
	}
	if got := ch.CheckAddr(d, netip.MustParseAddr("127.0.0.1")); !got.Allowed {
		t.Fatalf("validated addr refused: %q", got.Reason)
	}
	if got := ch.CheckAddr(d, netip.MustParseAddr("169.254.169.254")); got.Allowed || got.Reason != "metadata" {
		t.Fatalf("rebind not refused: %+v", got)
	}
	if got := ch.CheckAddr(d, netip.MustParseAddr("8.8.8.8")); got.Allowed {
		t.Fatal("unvalidated addr allowed")
	}
	if got := ch.CheckAddr(Decision{}, netip.MustParseAddr("127.0.0.1")); got.Allowed {
		t.Fatal("refused decision revived")
	}
}

func TestZeroDecisionIsRefused(t *testing.T) {
	if (Decision{}).Allowed {
		t.Fatal("zero Decision allowed")
	}
}

func TestPortDefaults(t *testing.T) {
	ch, _ := New(Policy{}, fakeResolver{})
	if d := ch.Check(context.Background(), "https://"+"10.0.0.1/"); d.Port != 443 {
		t.Fatalf("https port %d", d.Port)
	}
	if d := ch.Check(context.Background(), "http://"+"10.0.0.1:"+strconv.Itoa(8080)); d.Port != 8080 {
		t.Fatalf("port %d", d.Port)
	}
}

// TestNoNetworkImports asserts the package stays pure: no net, net/http, or
// other dialing packages (net/netip and net/url are fine).
func TestNoNetworkImports(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	banned := map[string]bool{"net": true, "net/http": true, "net/rpc": true, "net/smtp": true, "net/textproto": true, "os/exec": true, "crypto/tls": true}
	fset := token.NewFileSet()
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if banned[p] {
				t.Errorf("%s imports %s", f, p)
			}
		}
	}
}
