package parser

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadCA loads a PEM or DER encoded CA certificate.
// path must be a canonical, trusted path constructed by the caller.
func LoadCA(path string) (*x509.Certificate, error) {
	clean := filepath.Clean(path)
	if strings.Contains(clean, "..") {
		return nil, fmt.Errorf("path traversal detected in path: %s", path)
	}
	data, err := os.ReadFile(clean) //nolint:gosec // G304: path is cleaned and caller-validated
	if err != nil {
		return nil, err
	}
	
	// Attempt PEM decode first
	block, _ := pem.Decode(data)
	if block != nil {
		return x509.ParseCertificate(block.Bytes)
	}
	
	// Fall back to DER
	return x509.ParseCertificate(data)
}

// LoadCRL loads a DER or PEM encoded CRL.
// path must be a canonical, trusted path constructed by the caller.
func LoadCRL(path string) (*x509.RevocationList, error) {
	clean := filepath.Clean(path)
	if strings.Contains(clean, "..") {
		return nil, fmt.Errorf("path traversal detected in path: %s", path)
	}
	data, err := os.ReadFile(clean) //nolint:gosec // G304: path is cleaned and caller-validated
	if err != nil {
		return nil, err
	}
	
	// Attempt PEM decode first
	block, _ := pem.Decode(data)
	if block != nil {
		return x509.ParseRevocationList(block.Bytes)
	}
	
	return x509.ParseRevocationList(data)
}

// LoadPrivateKey loads a PEM or DER encoded private key (RSA, ECDSA, or Ed25519).
// path must be a canonical, trusted path constructed by the caller.
func LoadPrivateKey(path string) (crypto.Signer, error) {
	clean := filepath.Clean(path)
	if strings.Contains(clean, "..") {
		return nil, fmt.Errorf("path traversal detected in path: %s", path)
	}
	data, err := os.ReadFile(clean) //nolint:gosec // G304: path is cleaned and caller-validated
	if err != nil {
		return nil, err
	}
	
	var der []byte
	block, _ := pem.Decode(data)
	if block != nil {
		der = block.Bytes
	} else {
		der = data
	}

	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key.(crypto.Signer), nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("failed to parse private key from %s", path)
}
