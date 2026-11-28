package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"authzcoveval/result"
)

// F1: a signal must run the registered cleanups, then exit non-zero.
func TestSignalRunsCleanups(t *testing.T) {
	cleanups = nil
	ran := false
	addCleanup(func() { ran = true })
	ch := make(chan os.Signal, 1)
	code := make(chan int, 1)
	handleSignals(ch, func(c int) { code <- c })
	ch <- syscall.SIGINT
	select {
	case c := <-code:
		if c == 0 || !ran {
			t.Fatalf("exit code %d, cleanup ran %v", c, ran)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("signal handler did not exit")
	}
}

// F1: a failed `down` must be returned, not swallowed.
func TestDownStackReportsError(t *testing.T) {
	if err := downStack("p", func() error { return errors.New("boom") }); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("teardown error lost: %v", err)
	}
	if err := downStack("p", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}

// F1: run.sh must not exec (that prevents a trap) and must trap signals.
func TestRunShHasTrapAndNoExec(t *testing.T) {
	b, err := os.ReadFile("run.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "trap ") {
		t.Error("run.sh has no trap")
	}
	if strings.Contains(s, "exec go run") {
		t.Error("run.sh still execs go run")
	}
}

// F2: every file the harness reads must be trackable; build output and HARs stay ignored.
func TestGitignoreTrackability(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	ignored := func(p string) bool {
		return exec.Command("git", "check-ignore", "-q", p).Run() == nil
	}
	for _, p := range []string{"openapi.yaml", "compose.yaml", "identities.yaml", "groundtruth.yaml", "run.sh", "main.go"} {
		if ignored(p) {
			t.Errorf("%s is git-ignored but the harness needs it", p)
		}
	}
	for _, p := range []string{"rec.har", "rweval"} {
		if !ignored(p) {
			t.Errorf("%s should stay ignored", p)
		}
	}
}

// F5: the result must not depend on map iteration order.
func TestBuildResultDeterministic(t *testing.T) {
	images := map[string]string{"a": "sha256:1", "b": "sha256:2", "c": "sha256:3", "d": "sha256:4", "e": "sha256:5"}
	render := func() string {
		r := buildResult("authzcov v0 (commit x)", images, nil, nil)
		r.GeneratedAt = ""
		r.Machine = result.MachineInfo{}
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	first := render()
	for i := 0; i < 20; i++ {
		if got := render(); got != first {
			t.Fatalf("result differs between renders:\n%s\n%s", first, got)
		}
	}
}
