// side-by-side prints EM DV TLS CA - G3B as eMudhra issued it and as
// Sectigo cross-signed it: subject, issuer and the SHA-256 of the public key
// (the hash Go 1.27.3 and rustls-webpki 0.103.16 block). Same key, two
// issuers. Run from ~/app.
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
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

func keyHash(c *x509.Certificate) string {
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h[:])
}

func short(h string) string { return h[:16] + "..." + h[len(h)-8:] }

func main() {
	a := load("certs/EM-DV-TLS-CA-G3B.pem")
	b := load("certs/EM-DV-TLS-CA-G3B-AAA.pem")
	ha, hb := keyHash(a), keyHash(b)
	row := func(label, x, y string) { fmt.Printf("%-13s %-30s %s\n", label, x, y) }
	row("", "eMudhra's own", "Sectigo's cross-sign")
	row("subject", a.Subject.CommonName, b.Subject.CommonName)
	row("issuer", a.Issuer.CommonName, b.Issuer.CommonName)
	row("key SHA-256", short(ha), short(hb))
	fmt.Println()
	if ha == hb {
		fmt.Println("same key:", ha)
	} else {
		fmt.Println("different keys")
	}
}
