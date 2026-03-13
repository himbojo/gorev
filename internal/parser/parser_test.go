package parser

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mustGenerateCA(t *testing.T) ([]byte, crypto.Signer) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	return pemBytes, priv
}

func mustGenerateCRL(t *testing.T, caCert *x509.Certificate, caKey crypto.Signer) []byte {
	t.Helper()
	template := x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(time.Hour),
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, &template, caCert, caKey)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})
}

func TestLoadCA(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("Valid PEM", func(t *testing.T) {
		pemBytes, _ := mustGenerateCA(t)
		path := filepath.Join(tmpDir, "ca.pem")
		os.WriteFile(path, pemBytes, 0644)

		cert, err := LoadCA(path)
		if err != nil {
			t.Fatalf("failed to load CA: %v", err)
		}
		if cert.Subject.CommonName != "Test CA" {
			t.Errorf("expected common name 'Test CA', got %s", cert.Subject.CommonName)
		}
	})

	t.Run("Invalid PEM", func(t *testing.T) {
		path := filepath.Join(tmpDir, "invalid.pem")
		os.WriteFile(path, []byte("NOT A PEM"), 0644)

		_, err := LoadCA(path)
		if err == nil {
			t.Error("expected error for invalid PEM, got nil")
		}
	})

	t.Run("Missing File", func(t *testing.T) {
		path := filepath.Join(tmpDir, "missing.pem")
		_, err := LoadCA(path)
		if err == nil {
			t.Error("expected error for missing file, got nil")
		}
	})
}

func TestLoadCRL(t *testing.T) {
	tmpDir := t.TempDir()
	caPEM, caKey := mustGenerateCA(t)
	block, _ := pem.Decode(caPEM)
	caCert, _ := x509.ParseCertificate(block.Bytes)

	t.Run("Valid PEM CRL", func(t *testing.T) {
		crlPEM := mustGenerateCRL(t, caCert, caKey)
		path := filepath.Join(tmpDir, "test.crl")
		os.WriteFile(path, crlPEM, 0644)

		crl, err := LoadCRL(path)
		if err != nil {
			t.Fatalf("failed to load CRL: %v", err)
		}
		if crl == nil {
			t.Fatal("expected CRL, got nil")
		}
	})

	t.Run("Valid DER CRL", func(t *testing.T) {
		template := x509.RevocationList{
			Number:     big.NewInt(1),
			ThisUpdate: time.Now(),
			NextUpdate: time.Now().Add(time.Hour),
		}
		crlDER, _ := x509.CreateRevocationList(rand.Reader, &template, caCert, caKey)
		path := filepath.Join(tmpDir, "test.der.crl")
		os.WriteFile(path, crlDER, 0644)

		crl, err := LoadCRL(path)
		if err != nil {
			t.Fatalf("failed to load DER CRL: %v", err)
		}
		if crl == nil {
			t.Fatal("expected CRL, got nil")
		}
	})
}

func TestLoadPrivateKey(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("RSA PKCS1", func(t *testing.T) {
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		})
		path := filepath.Join(tmpDir, "rsa_pkcs1.pem")
		os.WriteFile(path, pemBytes, 0644)

		key, err := LoadPrivateKey(path)
		if err != nil {
			t.Fatalf("failed to load RSA PKCS1: %v", err)
		}
		if _, ok := key.(*rsa.PrivateKey); !ok {
			t.Errorf("expected *rsa.PrivateKey, got %T", key)
		}
	})

	t.Run("ECDSA", func(t *testing.T) {
		priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		derBytes, _ := x509.MarshalECPrivateKey(priv)
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: derBytes,
		})
		path := filepath.Join(tmpDir, "ec.pem")
		os.WriteFile(path, pemBytes, 0644)

		key, err := LoadPrivateKey(path)
		if err != nil {
			t.Fatalf("failed to load EC key: %v", err)
		}
		if _, ok := key.(*ecdsa.PrivateKey); !ok {
			t.Errorf("expected *ecdsa.PrivateKey, got %T", key)
		}
	})

	t.Run("PKCS8 RSA", func(t *testing.T) {
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		derBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: derBytes,
		})
		path := filepath.Join(tmpDir, "pkcs8.pem")
		os.WriteFile(path, pemBytes, 0644)

		key, err := LoadPrivateKey(path)
		if err != nil {
			t.Fatalf("failed to load PKCS8 key: %v", err)
		}
		if _, ok := key.(*rsa.PrivateKey); !ok {
			t.Errorf("expected *rsa.PrivateKey, got %T", key)
		}
	})

	t.Run("Invalid Key", func(t *testing.T) {
		path := filepath.Join(tmpDir, "invalid_key.pem")
		os.WriteFile(path, []byte("NOT A KEY"), 0644)

		_, err := LoadPrivateKey(path)
		if err == nil {
			t.Error("expected error for invalid key PEM, got nil")
		}
	})
}
