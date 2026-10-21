// gocheck verifies the real EM DV TLS CA - G3B (the certificate eMudhra's
// emSign Root TLS CA - G3 issued; no made-up leaf: Go checks a leaf's
// signature while it builds the chain, so a made-up leaf fails the same way
// on every version). It's built twice, with go1.27.2 and go1.27.3, as
// gocheck-1.27.2 and gocheck-1.27.3.
//
// With no SSL_CERT_FILE, Go on macOS hands the chain to the Mac's own
// verifier. With SSL_CERT_FILE set (Go 1.27+), Go checks the chain itself
// against that file, as it does on Linux.
//
// Run from ~/app. Prints file names only, never paths.
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	target = "certs/EM-DV-TLS-CA-G3B.pem"
	// emSign Root TLS CA - G3, cross-signed by emSign ECC Root CA - G3: the
	// link to the root that pre-fix root lists (certifi in July) carry.
	link = "certs/emSign-Root-TLS-CA-G3-by-ECC-G3.pem"
)

func load(path string) *x509.Certificate {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("cannot read %s: run this from ~/app\n", path)
		os.Exit(2)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		fmt.Printf("%s: not a PEM certificate\n", path)
		os.Exit(2)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		fmt.Printf("%s: %v\n", path, err)
		os.Exit(2)
	}
	return c
}

func main() {
	cert := load(target)
	opts := x509.VerifyOptions{Intermediates: x509.NewCertPool()}
	opts.Intermediates.AddCert(load(link))

	fmt.Printf("built with %s\n", runtime.Version())
	fmt.Printf("checking: %s, issued by %s\n", cert.Subject.CommonName, cert.Issuer.CommonName)
	who := "macOS"
	if f := os.Getenv("SSL_CERT_FILE"); f != "" {
		who = "Go's own check"
		fmt.Printf("roots: %s (SSL_CERT_FILE: Go checks the chain itself)\n", filepath.Base(f))
	} else if runtime.GOOS != "darwin" {
		who = runtime.GOOS
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		label := "rejected"
		if strings.Contains(err.Error(), "revoked") {
			label = "revoked"
		}
		fmt.Printf("%s: %s\n", who, label)
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%s: trusted\n", who)
	for _, ch := range chains {
		names := make([]string, len(ch))
		for i, c := range ch {
			names[i] = c.Subject.CommonName
		}
		fmt.Println("chain:", strings.Join(names, " <- "))
	}
}
