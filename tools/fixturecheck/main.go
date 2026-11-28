// Command fixturecheck fails when a committed fixture could hold real data:
// a JWT that was not minted for tests, or a HAR file that mentions a host
// outside the demo-host allowlist. Standard library only.
//
// Scope: only URLs with an http, https, ws or wss scheme are host-checked; bare
// hostnames without a scheme are deliberately not detected.
//
// Usage: go run ./tools/fixturecheck   (from the repository root)
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// testIssuer is the only "iss" a fixture JWT may carry without an allowlist entry.
const testIssuer = "authzcov-test"

const allowFile = "tools/fixturecheck/allow.txt"

// maxFileSize bounds what is read into memory per file or zip member.
const maxFileSize = 50 << 20

// sniffWindow is how much of a file is searched for "entries" before a HAR parse is tried.
const sniffWindow = 64 << 10

var jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)

// demoHosts: exact names, or "*.suffix" patterns that match any subdomain.
var demoHosts = []string{"localhost", "127.0.0.1", "::1", "*.test", "example.com", "*.example.com", "example.test"}

type failure struct {
	path   string
	line   int
	reason string
}

func (f failure) String() string {
	if f.line == 0 {
		return fmt.Sprintf("%s:%s", f.path, f.reason)
	}
	return fmt.Sprintf("%s:%d: %s", f.path, f.line, f.reason)
}

// allowlist maps path -> set of sha256 hex prefixes (12 chars) of allowed tokens.
type allowlist map[string]map[string]string

func tokenHash(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])[:12]
}

// parseAllowlist reads lines "path sha256prefix reason..."; '#' starts a comment.
func parseAllowlist(r io.Reader) (allowlist, error) {
	al := allowlist{}
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			return nil, fmt.Errorf("allow list line %d: want \"path hash12 reason\"", n)
		}
		if strings.HasPrefix(f[1], "host:") {
			if name := f[1][len("host:"):]; name == "" || strings.Contains(name, "*") {
				return nil, fmt.Errorf("allow list line %d: host entry needs a literal host name", n)
			}
			f[1] = hostKey(f[1][len("host:"):])
		} else if len(f[1]) != 12 {
			return nil, fmt.Errorf("allow list line %d: hash must be 12 hex chars", n)
		}
		if al[f[0]] == nil {
			al[f[0]] = map[string]string{}
		}
		al[f[0]][f[1]] = strings.Join(f[2:], " ")
	}
	return al, sc.Err()
}

// hostKey is the allowlist key (second field) for a per-path host entry: "host:NAME".
func hostKey(host string) string { return "host:" + strings.ToLower(host) }

func (al allowlist) allowsHost(path, host string) bool {
	_, ok := al[path][hostKey(host)]
	return ok
}

// hasHashEntry reports whether the path has a token-hash entry (host entries do not count).
func (al allowlist) hasHashEntry(path string) bool {
	for k := range al[path] {
		if !strings.HasPrefix(k, "host:") {
			return true
		}
	}
	return false
}

func (al allowlist) allows(path, tok string) bool {
	_, ok := al[path][tokenHash(tok)]
	return ok
}

func decodeSegment(s string) (map[string]any, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// checkToken returns "" when the token is acceptable, else the failure reason.
func checkToken(tok string) string {
	parts := strings.Split(tok, ".")
	if _, err := decodeSegment(parts[0]); err != nil {
		return "JWT-shaped string with undecodable header"
	}
	payload, err := decodeSegment(parts[1])
	if err != nil {
		return "JWT-shaped string with undecodable payload"
	}
	if iss, _ := payload["iss"].(string); iss != testIssuer {
		return fmt.Sprintf("JWT %s... has iss %q, want %q (or add \"path %s reason\" to %s)", tok[:12], iss, testIssuer, tokenHash(tok), allowFile)
	}
	return ""
}

func isBinary(b []byte) bool {
	head := b
	if len(head) > 8000 {
		head = head[:8000]
	}
	return bytes.IndexByte(head, 0) >= 0
}

// isTextFixture names extensions that are always host-scanned, even with NUL bytes.
func isTextFixture(lowerPath string) bool {
	for _, e := range []string{".json", ".yml", ".yaml", ".md", ".txt", ".sarif", ".html"} {
		if strings.HasSuffix(lowerPath, e) {
			return true
		}
	}
	return false
}

// scanJWTs checks every JWT-shaped byte sequence in a blob. Text files report
// line numbers; binary files report "offset N" in the reason and line 0.
func scanJWTs(path string, data []byte, al allowlist) []failure {
	var out []failure
	binary := isBinary(data)
	for _, loc := range jwtRe.FindAllIndex(data, -1) {
		tok := string(data[loc[0]:loc[1]])
		if al.allows(path, tok) {
			continue
		}
		reason := checkToken(tok)
		if reason == "" {
			continue
		}
		if binary {
			out = append(out, failure{path, 0, fmt.Sprintf("offset %d: %s", loc[0], reason)})
		} else {
			out = append(out, failure{path, bytes.Count(data[:loc[0]], []byte("\n")) + 1, reason})
		}
	}
	return out
}

// looksLikeHAR reports whether data is JSON whose top level has log.entries as an array.
// It only parses files that start with "{" and mention "entries" in the first 64 KiB.
func looksLikeHAR(data []byte) bool {
	t := bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	t = bytes.TrimLeft(t, " \t\r\n")
	if len(t) == 0 || t[0] != '{' {
		return false
	}
	head := t
	if len(head) > sniffWindow {
		head = head[:sniffWindow]
	}
	if !bytes.Contains(head, []byte(`"entries"`)) {
		return false
	}
	var doc struct {
		Log struct {
			Entries []json.RawMessage `json:"entries"`
		} `json:"log"`
	}
	return json.Unmarshal(t, &doc) == nil && doc.Log.Entries != nil
}

func hostAllowed(host string) bool {
	host = strings.ToLower(host)
	for _, p := range demoHosts {
		if rest, ok := strings.CutPrefix(p, "*."); ok {
			if strings.HasSuffix(host, "."+rest) {
				return true
			}
		} else if host == p {
			return true
		}
	}
	return false
}

// urlHostRe captures the host of http(s)/ws(s) URLs in free text (optional userinfo skipped).
var urlHostRe = regexp.MustCompile(`(?i)\b(?:https?|wss?)(?::(?:\\?/){2})(?:[^/\s"'<>@\\?#]*@)?(\[[0-9a-f:]+\]|[a-z0-9][a-z0-9._\-\x{80}-\x{10FFFF}]*)`)

// textHostAllowed is hostAllowed plus the RFC 2606 reserved names, which can never resolve.
func textHostAllowed(host string) bool {
	h := strings.ToLower(strings.Trim(host, "[]"))
	return hostAllowed(h) || h == "invalid" || strings.HasSuffix(h, ".invalid") || strings.HasSuffix(h, ".example")
}

// scanTextHosts fails every URL host in a text file that is neither a demo host
// nor allowlisted for this path. One failure per host per file.
func scanTextHosts(path string, data []byte, al allowlist) []failure {
	var out []failure
	seen := map[string]bool{}
	line, pos := 1, 0
	for _, m := range urlHostRe.FindAllSubmatchIndex(data, -1) {
		line += bytes.Count(data[pos:m[2]], []byte("\n"))
		pos = m[2]
		h := strings.ToLower(strings.TrimRight(string(data[m[2]:m[3]]), ".-_"))
		if h == "" || seen[h] || textHostAllowed(h) || al.allowsHost(path, h) {
			continue
		}
		seen[h] = true
		out = append(out, failure{path, line, fmt.Sprintf("URL host %q is not a demo host (allow with \"%s host:%s reason\")", h, path, h)})
	}
	return out
}

func lineOf(data []byte, needle string) int {
	i := bytes.Index(data, []byte(needle))
	if i < 0 {
		return 1
	}
	return bytes.Count(data[:i], []byte("\n")) + 1
}

// scanHAR checks every request URL host of one HAR document.
func scanHAR(path string, data []byte) []failure {
	var doc struct {
		Log struct {
			Entries []struct {
				Request struct {
					URL string `json:"url"`
				} `json:"request"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), &doc); err != nil {
		return []failure{{path, 1, "HAR is not valid JSON: " + err.Error()}}
	}
	var out []failure
	seen := map[string]bool{}
	for _, e := range doc.Log.Entries {
		u, err := url.Parse(e.Request.URL)
		if err != nil || u.Hostname() == "" {
			out = append(out, failure{path, lineOf(data, e.Request.URL), "request URL has no parsable host"})
			continue
		}
		h := u.Hostname()
		if !hostAllowed(h) && !seen[h] {
			seen[h] = true
			out = append(out, failure{path, lineOf(data, e.Request.URL), fmt.Sprintf("HAR request host %q is not a demo host", h)})
		}
	}
	return out
}

func scanZip(path string, data []byte, al allowlist) []failure {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return []failure{{path, 1, "cannot read zip: " + err.Error()}}
	}
	var out []failure
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := path + "!" + f.Name
		rc, err := f.Open()
		if err != nil {
			out = append(out, failure{name, 1, "cannot open zip member: " + err.Error()})
			continue
		}
		b, err := io.ReadAll(io.LimitReader(rc, maxFileSize+1))
		_ = rc.Close()
		if err != nil {
			out = append(out, failure{name, 1, "cannot read zip member: " + err.Error()})
			continue
		}
		if len(b) > maxFileSize {
			out = append(out, failure{name, 1, "zip member larger than 50 MiB, not scanned"})
			continue
		}
		out = append(out, scanContent(name, b, al)...)
	}
	return out
}

// scanContent dispatches on the (possibly "zip!member") name and the content.
// Every file is JWT-scanned; HAR host checks apply to *.har names and to any
// JSON with log.entries; zip members are scanned the same way.
func scanContent(path string, data []byte, al allowlist) []failure {
	var out []failure
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".har.zip"):
		return scanZip(path, data, al)
	case strings.HasSuffix(lower, ".zip") && bytes.HasPrefix(data, []byte("PK")):
		if zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err == nil && zr != nil {
			return scanZip(path, data, al)
		}
	}
	harName := strings.HasSuffix(lower, ".har")
	var harFails []failure
	if harName || looksLikeHAR(data) {
		harFails = scanHAR(path, data)
		out = append(out, harFails...)
	}
	if !harName && (isTextFixture(lower) || !isBinary(data)) {
	text:
		for _, f := range scanTextHosts(path, data, al) {
			q := f.reason[strings.Index(f.reason, `"`) : strings.Index(f.reason, `" is not`)+1]
			for _, h := range harFails {
				if strings.Contains(h.reason, q) {
					continue text // already reported by the HAR scan
				}
			}
			out = append(out, f)
		}
	}
	return append(out, scanJWTs(path, data, al)...)
}

func scanFile(root, rel string, al allowlist) []failure {
	full := filepath.Join(root, rel)
	st, err := os.Lstat(full)
	if err != nil || !st.Mode().IsRegular() {
		return nil // deleted from the worktree, or a symlink/submodule
	}
	slash := filepath.ToSlash(rel)
	if st.Size() > maxFileSize && !al.hasHashEntry(slash) {
		return []failure{{slash, 1, "file larger than 50 MiB, not scanned (allowlist the path with a hash entry in " + allowFile + " to accept it; host entries do not count)"}}
	}
	fh, err := os.Open(full) //nolint:gosec // paths come from git ls-files
	if err != nil {
		return []failure{{rel, 1, "cannot read: " + err.Error()}}
	}
	defer func() { _ = fh.Close() }()
	data, err := io.ReadAll(io.LimitReader(fh, maxFileSize))
	if err != nil {
		return []failure{{rel, 1, "cannot read: " + err.Error()}}
	}
	return scanContent(slash, data, al)
}

func scanFiles(root string, files []string, al allowlist) []failure {
	var out []failure
	for _, f := range files {
		out = append(out, scanFile(root, f, al)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].path != out[j].path {
			return out[i].path < out[j].path
		}
		return out[i].line < out[j].line
	})
	return out
}

func gitFiles(root string) ([]string, error) {
	cmd := exec.Command("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	cmd.Dir = root
	b, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	var files []string
	seen := map[string]bool{}
	for _, f := range strings.Split(string(b), "\x00") {
		if f != "" && !seen[f] {
			seen[f] = true
			files = append(files, f)
		}
	}
	return files, nil
}

func run(root string, stdout, stderr io.Writer) int {
	var al allowlist
	f, err := os.Open(filepath.Join(root, allowFile)) //nolint:gosec // fixed repo path
	switch {
	case err == nil:
		al, err = parseAllowlist(f)
		_ = f.Close()
		if err != nil {
			fmt.Fprintln(stderr, "fixturecheck:", err)
			return 2
		}
	case os.IsNotExist(err):
		al = allowlist{}
	default:
		fmt.Fprintln(stderr, "fixturecheck:", err)
		return 2
	}
	files, err := gitFiles(root)
	if err != nil {
		fmt.Fprintln(stderr, "fixturecheck:", err)
		return 2
	}
	fails := scanFiles(root, files, al)
	for _, fl := range fails {
		fmt.Fprintln(stdout, fl)
	}
	if len(fails) > 0 {
		fmt.Fprintf(stdout, "fixturecheck: FAIL, %d problem(s) in %d files\n", len(fails), len(files))
		return 1
	}
	fmt.Fprintf(stdout, "fixturecheck: ok, %d files scanned\n", len(files))
	return 0
}

func main() {
	os.Exit(run(".", os.Stdout, os.Stderr))
}
