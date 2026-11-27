package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeVampi answers every request with {} and every login with a token, except
// that the first failAdmin admin logins fail like a VAmPI book-title collision.
func fakeVampi(t *testing.T, failAdmin int32) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var adminFails, createdb atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/createdb":
			createdb.Add(1)
			_, _ = io.WriteString(w, `{"message":"Database populated."}`)
		case r.URL.Path == "/users/v1/login":
			if strings.Contains(string(b), `"admin"`) && adminFails.Load() < failAdmin {
				adminFails.Add(1)
				_, _ = io.WriteString(w, `{ "status": "fail", "message": "Username does not exist"}`)
				return
			}
			_, _ = io.WriteString(w, `{"auth_token":"x.y.z"}`)
		default:
			_, _ = io.WriteString(w, `{}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &createdb
}

func TestRecordSessionRetriesSetupError(t *testing.T) {
	clean, _ := fakeVampi(t, 0)
	want := len(recordSession(clean.URL, "honest", 1).entries)

	flaky, createdb := fakeVampi(t, 2)
	r := recordSession(flaky.URL, "honest", 5)
	if got := createdb.Load(); got != 3 {
		t.Errorf("/createdb called %d times, want 3 (two failed attempts + one clean)", got)
	}
	if len(r.entries) != want {
		t.Errorf("HAR has %d entries, want %d: failed attempts must be discarded", len(r.entries), want)
	}
	if !strings.HasSuffix(r.entries[0].Request.URL, "/createdb") {
		t.Errorf("first entry %s, want the clean attempt's /createdb", r.entries[0].Request.URL)
	}
}

func TestTryRecordRepanicsOtherErrors(t *testing.T) {
	r := newRecorder("http://127.0.0.1:1") // connection refused → plain string panic, not setupError
	defer func() {
		if recover() == nil {
			t.Fatal("non-setup panic was swallowed")
		}
	}()
	var last setupError
	tryRecord(r, "honest", &last)
}
