// Command record runs the scripted tenantshop session and writes a HAR file.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"tenantshop/record"
)

func main() {
	base := flag.String("base", "http://localhost:8090", "tenantshop base URL")
	out := flag.String("out", "testdata/raw/tenantshop.har", "HAR output file (relative to the working directory)")
	flag.Parse()
	har, err := record.Record(*base, &http.Client{Timeout: 10 * time.Second})
	if err == nil {
		err = os.MkdirAll(filepath.Dir(*out), 0o755)
	}
	if err == nil {
		err = os.WriteFile(*out, har, 0o600)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "record:", err)
		os.Exit(1)
	}
	fmt.Println("wrote", *out)
}
