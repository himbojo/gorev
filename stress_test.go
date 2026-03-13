//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/himbojo/gorev/internal/database"
	"github.com/himbojo/gorev/internal/parser"
	"github.com/himbojo/gorev/internal/server"
	"golang.org/x/crypto/ocsp"
)

const totalRevoked = 1_000_000

// TestLargeCRL generates a CRL with 1 million revoked certificates and
// validates the full pipeline: parse → Redis load → OCSP query.
// It reports latency metrics for each stage.
//
// Requires Redis on localhost:6379.
// Run: go test -v -tags integration -run TestLargeCRL -timeout 10m ./...
func TestLargeCRL(t *testing.T) {
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	ctx := context.Background()

	// ── Stage 0: Generate PKI in-memory ──────────────────────────────
	t.Log("Generating in-memory PKI (CA + responder)...")
	caKey, caCert := mustGenerateCA(t)
	respKey, respCert := mustGenerateResponder(t, caKey, caCert)

	// ── Stage 1: Generate CRL with 1M entries ────────────────────────
	t.Logf("Generating CRL with %d revoked entries...", totalRevoked)
	start := time.Now()

	revokedEntries := make([]x509.RevocationListEntry, totalRevoked)
	for i := range revokedEntries {
		revokedEntries[i] = x509.RevocationListEntry{
			SerialNumber:   big.NewInt(int64(i + 1)),
			RevocationTime: time.Now(),
		}
	}

	crlTemplate := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().Add(30 * 24 * time.Hour),
		RevokedCertificateEntries: revokedEntries,
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	if err != nil {
		t.Fatalf("Failed to create CRL: %v", err)
	}
	genDuration := time.Since(start)
	t.Logf("  CRL generation: %v (DER size: %.2f MB)", genDuration, float64(len(crlDER))/(1024*1024))

	// ── Stage 2: Write CRL to temp file and parse it back ────────────
	tmpDir := t.TempDir()
	crlPath := tmpDir + "/stress.crl"
	if err := os.WriteFile(crlPath, crlDER, 0644); err != nil {
		t.Fatalf("Failed to write CRL file: %v", err)
	}

	start = time.Now()
	parsedCRL, err := parser.LoadCRL(crlPath)
	if err != nil {
		t.Fatalf("Failed to parse CRL: %v", err)
	}
	parseDuration := time.Since(start)
	t.Logf("  CRL parse:      %v (%d revoked entries)", parseDuration, len(parsedCRL.RevokedCertificates))

	if len(parsedCRL.RevokedCertificates) != totalRevoked {
		t.Fatalf("Expected %d revoked certs, got %d", totalRevoked, len(parsedCRL.RevokedCertificates))
	}

	// ── Stage 3: Load into Redis ─────────────────────────────────────
	db := database.New(redisAddr, os.Getenv("REDIS_PASSWORD"))
	caName := caCert.Subject.CommonName

	revokedSerials := make([]*big.Int, 0, totalRevoked)
	for _, rev := range parsedCRL.RevokedCertificates {
		revokedSerials = append(revokedSerials, rev.SerialNumber)
	}

	start = time.Now()
	if err := db.ReplaceBulkRevocations(ctx, caName, revokedSerials); err != nil {
		t.Fatalf("Failed to load revocations into Redis: %v", err)
	}
	dbLoadDuration := time.Since(start)
	t.Logf("  DB load:        %v (%d serials)", dbLoadDuration, len(revokedSerials))

	// Clear any stale OCSP cache before querying
	if err := db.InvalidateCache(ctx); err != nil {
		t.Fatalf("Failed to invalidate cache: %v", err)
	}

	// ── Stage 4: Spin up OCSP test server ────────────────────────────
	ocspPrefixes := []string{"/ocsp"}
	srv := server.New(db, tmpDir, ocspPrefixes)
	srv.UpdateCerts(
		[]*x509.Certificate{caCert},
		[]*x509.Certificate{respCert},
		[]crypto.Signer{respKey},
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/ocsp", srv.HandleOCSP)
	mux.HandleFunc("/ocsp/", srv.HandleOCSP)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// ── Stage 5: OCSP Lookups with latency ───────────────────────────

	// queryOCSP builds an OCSP request for the given serial and POSTs it.
	queryOCSP := func(serial *big.Int) (int, time.Duration) {
		// Create a minimal dummy certificate with the desired serial.
		dummyCert := &x509.Certificate{SerialNumber: serial}
		reqBytes, err := ocsp.CreateRequest(dummyCert, caCert, nil)
		if err != nil {
			t.Fatalf("Failed to create OCSP request for serial %s: %v", serial, err)
		}

		start := time.Now()
		resp, err := http.Post(ts.URL+"/ocsp", "application/ocsp-request", bytes.NewReader(reqBytes))
		if err != nil {
			t.Fatalf("OCSP POST failed: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		elapsed := time.Since(start)

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("OCSP request returned status %d: %s", resp.StatusCode, string(body))
		}
		return resp.StatusCode, elapsed
	}

	// 5a. Revoked serial (serial 500000 — middle of the CRL)
	t.Log("Querying OCSP for a revoked serial (500000)...")
	_, revokedLatency := queryOCSP(big.NewInt(500_000))
	t.Logf("  OCSP revoked:   %v", revokedLatency)

	// 5b. Good serial (serial 2000000 — not in the CRL)
	t.Log("Querying OCSP for a good serial (2000000)...")
	_, goodLatency := queryOCSP(big.NewInt(2_000_000))
	t.Logf("  OCSP good:      %v", goodLatency)

	// 5c. Cached revoked lookup (repeat serial 500000)
	t.Log("Querying OCSP for a cached serial (500000 again)...")
	_, cachedLatency := queryOCSP(big.NewInt(500_000))
	t.Logf("  OCSP cached:    %v", cachedLatency)

	// 5d. Batch latency: query 100 revoked serials spread across the range
	t.Log("Querying 100 revoked serials for average latency...")
	var totalBatchDuration time.Duration
	batchSize := 100
	for i := 0; i < batchSize; i++ {
		serial := big.NewInt(int64(i*10_000 + 1))
		_, d := queryOCSP(serial)
		totalBatchDuration += d
	}
	avgLatency := totalBatchDuration / time.Duration(batchSize)
	t.Logf("  OCSP avg (100): %v (total: %v)", avgLatency, totalBatchDuration)

	// ── Summary ──────────────────────────────────────────────────────
	t.Log("")
	t.Log("╔══════════════════════════════════════════════════════════╗")
	t.Log("║            STRESS TEST RESULTS SUMMARY                  ║")
	t.Log("╠══════════════════════════════════════════════════════════╣")
	t.Logf("║  Revoked Entries:       %10d                      ║", totalRevoked)
	t.Logf("║  CRL DER Size:          %10.2f MB                  ║", float64(len(crlDER))/(1024*1024))
	t.Log("╠══════════════════════════════════════════════════════════╣")
	t.Logf("║  CRL Generation:        %10v                      ║", genDuration.Truncate(time.Millisecond))
	t.Logf("║  CRL Parse:             %10v                      ║", parseDuration.Truncate(time.Millisecond))
	t.Logf("║  Redis Bulk Load:       %10v                      ║", dbLoadDuration.Truncate(time.Millisecond))
	t.Logf("║  OCSP Revoked Lookup:   %10v                      ║", revokedLatency.Truncate(time.Microsecond))
	t.Logf("║  OCSP Good Lookup:      %10v                      ║", goodLatency.Truncate(time.Microsecond))
	t.Logf("║  OCSP Cached Lookup:    %10v                      ║", cachedLatency.Truncate(time.Microsecond))
	t.Logf("║  OCSP Avg (100 reqs):   %10v                      ║", avgLatency.Truncate(time.Microsecond))
	t.Log("╚══════════════════════════════════════════════════════════╝")

	// ── Cleanup: remove the test keys from Redis ─────────────────────
	if err := db.InvalidateCache(ctx); err != nil {
		t.Logf("Warning: failed to clean up OCSP cache: %v", err)
	}
}

// mustGenerateCA creates a self-signed ECDSA CA certificate for testing.
func mustGenerateCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Stress-Test-CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse CA cert: %v", err)
	}
	return key, cert
}

// mustGenerateResponder creates an OCSP responder cert signed by the given CA.
func mustGenerateResponder(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate responder key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Stress-Test-Responder"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create responder cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse responder cert: %v", err)
	}
	return key, cert
}
