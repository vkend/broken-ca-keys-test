// mkleaf makes the tests' made-up leaf: a certificate for api.example.com
// whose issuer name and authority key ID match the real EM DV TLS CA - G3B,
// signed with a throwaway key generated here and never written to disk. The
// signature therefore cannot verify under the real intermediate's key, and
// no eMudhra private key is used, computed or downloaded.
//
//	mkleaf certs/EM-DV-TLS-CA-G3B.pem > certs/api.example.com.pem
//	mkleaf certs/EM-DV-TLS-CA-G3B.pem <leaf-key.pem> > leaf.pem
//
// With a second argument it also writes the leaf's own key (a throwaway
// P-256 key, never an eMudhra one) for the in-memory TLS handshakes (setup.sh's ~/app/server, confirm-facts.sh);
// the signer's key is still dropped.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func main() {
	b, err := os.ReadFile(os.Args[1]) // the real intermediate (public certificate)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkleaf: cannot read the intermediate")
		os.Exit(1)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		fmt.Fprintln(os.Stderr, "mkleaf: not a PEM certificate")
		os.Exit(1)
	}
	real, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkleaf:", err)
		os.Exit(1)
	}
	throwaway, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// A stand-in parent: the real intermediate's name and key ID, our own key.
	parent := &x509.Certificate{
		RawSubject:   real.RawSubject,
		SubjectKeyId: real.SubjectKeyId,
		PublicKey:    throwaway.Public(),
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: "api.example.com"},
		DNSNames:     []string{"api.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, leafKey.Public(), throwaway)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkleaf:", err)
		os.Exit(1)
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	if len(os.Args) > 2 {
		k, _ := x509.MarshalPKCS8PrivateKey(leafKey)
		if err := os.WriteFile(os.Args[2], pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "mkleaf:", err)
			os.Exit(1)
		}
	}
}
