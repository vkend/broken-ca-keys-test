// gofacts: Go's own certificate check (crypto/x509) on any Go version and OS:
// the real EM DV TLS CA - G3B, with emSign Root TLS CA - G3's cross-sign as
// the intermediate, against the root list given as opts.Roots. With Roots
// set, Go never asks the operating system, so this is the check a Go program
// on Linux makes. confirm-facts.sh builds it with go1.26.9, go1.26.10,
// go1.27.2 and go1.27.3.
//
//	gofacts <roots.pem> <intermediate.pem> <link.pem>
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"runtime"
	"strings"
)

func main() {
	roots := x509.NewCertPool()
	b, _ := os.ReadFile(os.Args[1])
	roots.AppendCertsFromPEM(b)
	cert := parse(os.Args[2])
	inter := x509.NewCertPool()
	inter.AddCert(parse(os.Args[3]))
	_, err := cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter})
	if err != nil {
		fmt.Printf("%s, Go's own check: rejected (%v)\n", runtime.Version(), strings.TrimPrefix(err.Error(), "x509: "))
		return
	}
	fmt.Printf("%s, Go's own check: trusted\n", runtime.Version())
}

func parse(path string) *x509.Certificate {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("cannot read", path)
		os.Exit(2)
	}
	blk, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		fmt.Println(path, err)
		os.Exit(2)
	}
	return c
}
