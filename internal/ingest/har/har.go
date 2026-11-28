// Package har streams HAR files into redacted model.Exchange values.
package har

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/url"
	"path"
	"strings"

	"authzcov/internal/model"
	"authzcov/internal/redact"
)

// MaxBody is the largest request or response body kept.
const MaxBody = 64 << 10

// Extractor turns request headers into a redacted credential. lookup is a
// case-insensitive header lookup over the request headers (all values, in order).
type Extractor func(lookup func(name string) []string) model.Credential

// Options configure Exchanges.
type Options struct {
	Source  string    // label used in Exchange.Source, normally the HAR file's base name
	Extract Extractor // required
	// QueryKeys are the only query parameter names kept in Exchange.Query;
	// everything else in the query string is dropped (it may hold tokens).
	QueryKeys []string
}

// Stats counts what ingest kept and dropped.
type Stats struct {
	Entries      int // all entries seen
	Kept         int
	Static       int // dropped: static asset
	Options      int // dropped: OPTIONS preflight
	Status0      int // dropped: status 0 (aborted/blocked)
	BadURL       int // dropped: unparsable or non-absolute URL
	BodyTooLarge int // bodies dropped because > MaxBody (entry still kept)
}

type header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type entry struct {
	Request struct {
		Method   string   `json:"method"`
		URL      string   `json:"url"`
		Headers  []header `json:"headers"`
		PostData struct {
			MimeType string `json:"mimeType"`
			Text     string `json:"text"`
		} `json:"postData"`
	} `json:"request"`
	Response struct {
		Status  int `json:"status"`
		Content struct {
			MimeType string `json:"mimeType"`
			Text     string `json:"text"`
			Encoding string `json:"encoding"`
		} `json:"content"`
	} `json:"response"`
}

var staticExt = map[string]bool{
	".js": true, ".mjs": true, ".css": true, ".map": true, ".png": true, ".jpg": true,
	".jpeg": true, ".gif": true, ".svg": true, ".ico": true, ".webp": true, ".avif": true,
	".bmp": true, ".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".mp4": true, ".webm": true, ".mp3": true, ".wav": true,
}

var staticMIME = map[string]bool{
	"text/css": true, "text/javascript": true,
	"application/javascript": true, "application/x-javascript": true,
}

var staticMIMEPrefix = []string{"image/", "font/", "audio/", "video/", "application/font-"}

// Exchanges streams log.entries one at a time. st may be nil. On a decode
// error it yields (nil, err) once and stops.
func Exchanges(r io.Reader, opt Options, st *Stats) iter.Seq2[*model.Exchange, error] {
	return func(yield func(*model.Exchange, error) bool) {
		if opt.Extract == nil {
			yield(nil, errors.New("har: no credential extractor configured"))
			return
		}
		if st == nil {
			st = &Stats{}
		}
		s := &stream{dec: json.NewDecoder(r), opt: opt, st: st}
		if err := s.run(yield); err != nil {
			yield(nil, fmt.Errorf("har: %s: entry %d: %w", opt.Source, st.Entries, err))
		}
	}
}

type stream struct {
	dec *json.Decoder
	opt Options
	st  *Stats
}

var errStopped = errors.New("stopped")

func (s *stream) run(yield func(*model.Exchange, error) bool) error {
	err := s.top(yield)
	if errors.Is(err, errStopped) {
		return nil
	}
	return err
}

func (s *stream) top(yield func(*model.Exchange, error) bool) error {
	if err := s.expect('{'); err != nil {
		return fmt.Errorf("top level: %w", err)
	}
	return s.object(func(key string) error {
		if key != "log" {
			return s.skip()
		}
		return s.log(yield)
	})
}

func (s *stream) log(yield func(*model.Exchange, error) bool) error {
	tok, err := s.dec.Token()
	if err != nil {
		return err
	}
	if tok != json.Delim('{') {
		return s.skipFrom(tok)
	}
	return s.object(func(key string) error {
		if key != "entries" {
			return s.skip()
		}
		return s.entries(yield)
	})
}

func (s *stream) entries(yield func(*model.Exchange, error) bool) error {
	tok, err := s.dec.Token()
	if err != nil {
		return err
	}
	if tok != json.Delim('[') {
		return s.skipFrom(tok)
	}
	for s.dec.More() {
		var e entry
		if err := s.dec.Decode(&e); err != nil {
			return err
		}
		x := s.convert(&e, s.st.Entries)
		s.st.Entries++
		if x != nil && !yield(x, nil) {
			return errStopped
		}
	}
	_, err = s.dec.Token()
	return err
}

// object calls fn for each key of an object whose '{' was already consumed;
// fn must consume the value.
func (s *stream) object(fn func(key string) error) error {
	for s.dec.More() {
		tok, err := s.dec.Token()
		if err != nil {
			return err
		}
		key, _ := tok.(string)
		if err := fn(key); err != nil {
			return err
		}
	}
	_, err := s.dec.Token()
	return err
}

func (s *stream) expect(d json.Delim) error {
	tok, err := s.dec.Token()
	if err != nil {
		return err
	}
	if tok != d {
		return fmt.Errorf("expected %q", rune(d))
	}
	return nil
}

func (s *stream) skip() error {
	tok, err := s.dec.Token()
	if err != nil {
		return err
	}
	return s.skipFrom(tok)
}

// skipFrom consumes the rest of the value that began with tok.
func (s *stream) skipFrom(tok json.Token) error {
	d, ok := tok.(json.Delim)
	if !ok || d == '}' || d == ']' {
		return nil
	}
	for depth := 1; depth > 0; {
		t, err := s.dec.Token()
		if err != nil {
			return err
		}
		if d, ok := t.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else {
				depth--
			}
		}
	}
	return nil
}

// convert returns nil when the entry is dropped (and counted).
func (s *stream) convert(e *entry, idx int) *model.Exchange {
	method := strings.ToUpper(e.Request.Method)
	u, err := url.Parse(e.Request.URL)
	if err != nil || !u.IsAbs() || u.Host == "" {
		s.st.BadURL++
		return nil
	}
	switch {
	case method == "OPTIONS":
		s.st.Options++
		return nil
	case e.Response.Status == 0:
		s.st.Status0++
		return nil
	case isStatic(u.EscapedPath(), e.Response.Content.MimeType):
		s.st.Static++
		return nil
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	s.st.Kept++
	return &model.Exchange{
		Query:    pickQuery(u.RawQuery, s.opt.QueryKeys),
		Source:   fmt.Sprintf("%s#%d", s.opt.Source, idx),
		Method:   method,
		Host:     u.Host,
		Path:     p,
		Cred:     s.opt.Extract(lookupFunc(e.Request.Headers)),
		Status:   e.Response.Status,
		ReqJSON:  s.jsonBody(e.Request.PostData.MimeType, e.Request.PostData.Text, false),
		RespJSON: s.jsonBody(e.Response.Content.MimeType, e.Response.Content.Text, e.Response.Content.Encoding == "base64"),
	}
}

func lookupFunc(hs []header) func(string) []string {
	m := make(map[string][]string, len(hs))
	for _, h := range hs {
		k := strings.ToLower(h.Name)
		m[k] = append(m[k], h.Value)
	}
	return func(name string) []string { return m[strings.ToLower(name)] }
}

func isStatic(escPath, mime string) bool {
	if staticExt[strings.ToLower(path.Ext(path.Base(escPath)))] {
		return true
	}
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(mime, ";", 2)[0]))
	if staticMIME[mt] {
		return true
	}
	for _, p := range staticMIMEPrefix {
		if strings.HasPrefix(mt, p) {
			return true
		}
	}
	return false
}

func (s *stream) jsonBody(mime, text string, b64 bool) []byte {
	if text == "" || !strings.Contains(strings.ToLower(mime), "json") {
		return nil
	}
	body := []byte(text)
	if b64 {
		dec, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			return nil
		}
		body = dec
	}
	if len(body) > MaxBody {
		s.st.BodyTooLarge++
		return nil
	}
	out, err := redact.JSON(body)
	if err != nil {
		return nil
	}
	return out
}

// pickQuery decodes raw and returns the values of the wanted keys only. A
// malformed query yields nothing (fail closed to unknown).
func pickQuery(raw string, keys []string) map[string][]string {
	if raw == "" || len(keys) == 0 {
		return nil
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return nil
	}
	var out map[string][]string
	for _, k := range keys {
		if v, ok := q[k]; ok {
			if out == nil {
				out = map[string][]string{}
			}
			out[k] = v
		}
	}
	return out
}
