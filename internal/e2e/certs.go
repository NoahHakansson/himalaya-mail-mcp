//go:build integration

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// KeyPair is a PEM certificate and its PEM (PKCS#8) private key on disk.
type KeyPair struct {
	CertFile string
	KeyFile  string
}

// PKI is the set of throwaway certificates the integration tests use.
// Every key is P-256.
type PKI struct {
	Dir      string
	CA       KeyPair // trusted test CA
	Leaf     KeyPair // signed by CA for localhost and 127.0.0.1; the fixture default
	WrongSAN KeyPair // signed by CA for wrong.test only
	RogueCA  KeyPair // an unrelated CA that signed nothing the fixture serves
	Bridge   KeyPair // self-signed, CA-marked leaf for IP 127.0.0.1, shaped like Proton Bridge's
}

type issuer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// NewPKI generates a fresh PKI in a private temp dir removed at cleanup.
// Certificates are written 0644 and keys 0600.
func NewPKI(t testing.TB) *PKI {
	t.Helper()
	p := &PKI{Dir: TempDir(t)}
	now := time.Now()
	ca := func(cn string) *x509.Certificate {
		return &x509.Certificate{
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(48 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
	}
	leaf := func(cn string, dns []string, ips []net.IP) *x509.Certificate {
		return &x509.Certificate{
			Subject:               pkix.Name{CommonName: cn},
			DNSNames:              dns,
			IPAddresses:           ips,
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(48 * time.Hour),
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
	}
	loopback := []net.IP{net.IPv4(127, 0, 0, 1)}

	var caIssuer *issuer
	caIssuer, p.CA = p.issue(t, "ca", ca("hmcp e2e CA"), nil)
	_, p.Leaf = p.issue(t, "leaf", leaf("localhost", []string{"localhost"}, loopback), caIssuer)
	_, p.WrongSAN = p.issue(t, "wrong-san", leaf("wrong.test", []string{"wrong.test"}, nil), caIssuer)
	_, p.RogueCA = p.issue(t, "rogue-ca", ca("hmcp e2e rogue CA"), nil)
	// Bridge's vault certificate (internal/certs/tls.go): self-signed, IsCA,
	// CN and the only SAN 127.0.0.1, KeyUsage including CertSign, 20 years.
	_, p.Bridge = p.issue(t, "bridge", &x509.Certificate{
		Subject:               pkix.Name{Organization: []string{"Proton AG"}, CommonName: "127.0.0.1"},
		IPAddresses:           loopback,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(20 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, nil)
	return p
}

// issue signs tmpl with parent (self-signed when parent is nil) and writes
// <name>.pem and <name>.key.
func (p *PKI) issue(t testing.TB, name string, tmpl *x509.Certificate, parent *issuer) (*issuer, KeyPair) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if tmpl.SerialNumber, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127)); err != nil {
		t.Fatal(err)
	}
	signer := &issuer{cert: tmpl, key: key}
	if parent != nil {
		signer = parent
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer.cert, &key.PublicKey, signer.key)
	if err != nil {
		t.Fatalf("create %s certificate: %v", name, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	kp := KeyPair{CertFile: filepath.Join(p.Dir, name+".pem"), KeyFile: filepath.Join(p.Dir, name+".key")}
	writeFile(t, kp.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	writeFile(t, kp.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	return &issuer{cert: cert, key: key}, kp
}

// writeFile writes data with exactly mode perm, regardless of the umask.
func writeFile(t testing.TB, path string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
}
