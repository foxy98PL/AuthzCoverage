// Command authzcov reports API authorization test coverage.
package main

import (
	"os"

	"authzcov/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
