package parser

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadCA loads a PEM or DER encoded CA certificate.
func LoadCA(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
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
func LoadCRL(path string) (*x509.RevocationList, error) {
	data, err := os.ReadFile(path)
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
func LoadPrivateKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
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
