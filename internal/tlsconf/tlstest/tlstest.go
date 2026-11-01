// internal/tlsconf/tlstest/tlstest.go
// Package tlstest generates throwaway CAs and certificates for TLS tests.
// Nothing is checked in: every test mints its own material.
package tlstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// CA is a self-signed certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	PEM  []byte
}

// Pair is a leaf certificate and its key, PEM-encoded.
type Pair struct {
	Cert    *x509.Certificate
	CertPEM []byte
	KeyPEM  []byte
}

var serial atomic.Int64

func nextSerial() *big.Int {
	return big.NewInt(serial.Add(1))
}

// NewCA mints a CA named cn.
func NewCA(t testing.TB, cn string) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{Cert: cert, Key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// Server issues a server certificate valid for localhost and 127.0.0.1.
func (ca *CA) Server(t testing.TB, cn string) *Pair {
	t.Helper()
	return ca.issue(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: cn},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
}

// Client issues a client certificate carrying the given URI SANs.
func (ca *CA) Client(t testing.TB, cn string, uris ...string) *Pair {
	t.Helper()
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: cn},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	for _, s := range uris {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = append(tmpl.URIs, u)
	}
	return ca.issue(t, tmpl)
}

func (ca *CA) issue(t testing.TB, tmpl *x509.Certificate) *Pair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SerialNumber = nextSerial()
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(24 * time.Hour)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &Pair{
		Cert:    cert,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}

// TLSCertificate returns the pair as a tls.Certificate for client configs.
func (p *Pair) TLSCertificate(t testing.TB) tls.Certificate {
	t.Helper()
	c, err := tls.X509KeyPair(p.CertPEM, p.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Write stores the pair as <dir>/<name>.crt and <dir>/<name>.key and returns
// both paths.
func (p *Pair) Write(t testing.TB, dir, name string) (certFile, keyFile string) {
	t.Helper()
	certFile = filepath.Join(dir, name+".crt")
	keyFile = filepath.Join(dir, name+".key")
	WriteFile(t, certFile, p.CertPEM)
	WriteFile(t, keyFile, p.KeyPEM)
	return certFile, keyFile
}

// WriteCA stores the CA certificate as <dir>/<name>.crt and returns the path.
func (ca *CA) WriteCA(t testing.TB, dir, name string) string {
	t.Helper()
	f := filepath.Join(dir, name+".crt")
	WriteFile(t, f, ca.PEM)
	return f
}

// Pool returns a cert pool containing only this CA.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// WriteFile writes data to path, failing the test on error.
func WriteFile(t testing.TB, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
