package credentials

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

// F4: control characters in an extracted token are rejected, and a cookie
// apply rejects cookie-structure characters.
func TestTokenCharsRejected(t *testing.T) {
	for _, tc := range []struct {
		tok   string
		apply Apply
		ok    bool
	}{
		{"abc", Apply{Kind: "bearer"}, true},
		{"a\x01b", Apply{Kind: "bearer"}, false},
		{"a\x7fb", Apply{Kind: "header", Name: "X-T"}, false},
		{"a\tb", Apply{Kind: "bearer"}, false},
		{"a=1; admin=true", Apply{Kind: "cookie", Name: "sid"}, false},
		{"a;b", Apply{Kind: "cookie", Name: "sid"}, false},
		{"a,b", Apply{Kind: "cookie", Name: "sid"}, false},
		{"a b", Apply{Kind: "cookie", Name: "sid"}, false},
		{"a.b-c_d=", Apply{Kind: "cookie", Name: "sid"}, true},
	} {
		rec := goodRecipe()
		rec.Apply = tc.apply
		p := NewProvider(map[string]Recipe{"alice": rec})
		p.Lookup = envMap(map[string]string{"ALICE_USER": "a", "ALICE_PASS": "pw"})
		body := fmt.Sprintf(`{"access_token":%q}`, tc.tok)
		d := &fakeDoer{resp: map[string]fakeResp{"/auth/login": {200, jsonHdr(), body, nil}}}
		_, err := p.For(context.Background(), "alice", d)
		if (err == nil) != tc.ok {
			t.Errorf("tok %q apply %v: err=%v want ok=%v", tc.tok, tc.apply, err, tc.ok)
		}
	}
}

// F6
func TestForbiddenApplyHeadersMore(t *testing.T) {
	for _, h := range []string{"Proxy-Authorization", "TE", "Upgrade", "X-Forwarded-For", "X-Forwarded-Host"} {
		if _, err := ParseApply("header:" + h); err == nil {
			t.Errorf("%s accepted", h)
		}
	}
}

// F8: env secrets must not print a fingerprint of a low-entropy password.
func TestEnvSecretNoFingerprint(t *testing.T) {
	s, err := loadEnv("ALICE_PASS", envMap(map[string]string{"ALICE_PASS": "hunter2"}))
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{s.String(), fmt.Sprintf("%v %+v %#v %x", s, s, s, s)} {
		if !strings.Contains(out, "[REDACTED") || strings.Contains(out, "REDACTED:") {
			t.Fatalf("env secret prints fingerprint: %s", out)
		}
	}
}

// F2: env check is a separate probe-time step.
func TestRecipeCheckEnv(t *testing.T) {
	r := goodRecipe()
	err := r.CheckEnv(envMap(map[string]string{"ALICE_USER": "a"}))
	if err == nil || !strings.Contains(err.Error(), "ALICE_PASS") || !strings.Contains(err.Error(), "fields.password") {
		t.Fatalf("err = %v", err)
	}
	if err := r.CheckEnv(envMap(map[string]string{"ALICE_USER": "a", "ALICE_PASS": "x"})); err != nil {
		t.Fatal(err)
	}
	p := NewProvider(map[string]Recipe{"alice": r})
	p.Lookup = envMap(map[string]string{"ALICE_USER": "a"})
	if err := p.CheckEnv(); err == nil || !strings.Contains(err.Error(), "alice") || !strings.Contains(err.Error(), "ALICE_PASS") {
		t.Fatalf("provider err = %v", err)
	}
}

type blockDoer struct {
	slow    chan struct{}
	started chan struct{}
}

func (d *blockDoer) Do(ctx context.Context, req LoginRequest) (LoginResponse, error) {
	if req.Path == "/slow" {
		close(d.started)
		select {
		case <-d.slow:
		case <-ctx.Done():
			return LoginResponse{}, ctx.Err()
		}
	}
	return LoginResponse{Status: 200, Header: jsonHdr(), Body: nopBody(`{"access_token":"t"}`)}, nil
}

// F9: a slow login for one identity must not block another.
func TestProviderPerIdentityLocking(t *testing.T) {
	slow, fast := goodRecipe(), goodRecipe()
	slow.Path, fast.Path = "/slow", "/fast"
	p := NewProvider(map[string]Recipe{"alice": slow, "bob": fast})
	p.Lookup = envMap(map[string]string{"ALICE_USER": "a", "ALICE_PASS": "pw"})
	d := &blockDoer{slow: make(chan struct{}), started: make(chan struct{})}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = p.For(context.Background(), "alice", d) }()
	<-d.started
	done := make(chan error, 1)
	go func() { _, err := p.For(context.Background(), "bob", d); done <- err }()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	close(d.slow)
	wg.Wait()
}

// F9: a cancelled context is not cached as a permanent failure.
func TestProviderCancelNotCached(t *testing.T) {
	slow := goodRecipe()
	slow.Path = "/slow"
	p := NewProvider(map[string]Recipe{"alice": slow})
	p.Lookup = envMap(map[string]string{"ALICE_USER": "a", "ALICE_PASS": "pw"})
	d := &blockDoer{slow: make(chan struct{}), started: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.For(ctx, "alice", d); err == nil {
		t.Fatal("want error")
	}
	d2 := &blockDoer{slow: make(chan struct{}), started: make(chan struct{})}
	close(d2.slow)
	if _, err := p.For(context.Background(), "alice", d2); err != nil {
		t.Fatalf("cached cancel: %v", err)
	}
}

func nopBody(s string) io.ReadCloser { return io.NopCloser(strings.NewReader(s)) }
