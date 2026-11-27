package cli

import (
	"fmt"
	"os"
	"testing"
)

// TestMain redirects the default --out directory so tests that run coverage
// without --out never leave authzcov-out/ in the package directory.
// pkgDir is the package directory, for paths that must survive t.Chdir.
var pkgDir string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "authzcov-cli-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defaultOut = dir
	if pkgDir, err = os.Getwd(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
