// Command tenantshop serves the tenantshop demo API (seeded cross-tenant bug, KAN-74).
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"tenantshop/shop"
)

func main() {
	def := os.Getenv("ADDR")
	if def == "" {
		def = ":8080"
	}
	addr := flag.String("addr", def, "listen address (env ADDR)")
	flag.Parse()
	srv := &http.Server{Addr: *addr, Handler: shop.NewServer(), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("tenantshop listening on %s", *addr)
	log.Fatal(srv.ListenAndServe())
}
