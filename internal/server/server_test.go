package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/himbojo/gorev/internal/database"
	"golang.org/x/crypto/ocsp"
)

func mustGeneratePKI(t *testing.T) (*x509.Certificate, crypto.Signer, *x509.Certificate, crypto.Signer) {
	t.Helper()
	// CA
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:          true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	// Responder
	respKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	respTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Responder"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}
	respDER, _ := x509.CreateCertificate(rand.Reader, respTemplate, caCert, &respKey.PublicKey, caKey)
	respCert, _ := x509.ParseCertificate(respDER)

	return caCert, caKey, respCert, respKey
}

func TestHandleOCSP(t *testing.T) {
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	db := database.New(redisAddr, os.Getenv("REDIS_PASSWORD"))
	ctx := context.Background()
	
	// Skip if Redis is not available
	if err := db.InvalidateCache(ctx); err != nil {
		t.Skip("Redis not available for server tests")
	}

	caCert, _, respCert, respKey := mustGeneratePKI(t)
	s := New(db, "/tmp", []string{"/ocsp"})
	s.UpdateCerts([]*x509.Certificate{caCert}, []*x509.Certificate{respCert}, []crypto.Signer{respKey})

	t.Run("POST Valid Request", func(t *testing.T) {
		dummyCert := &x509.Certificate{SerialNumber: big.NewInt(100)}
		reqReq, _ := ocsp.CreateRequest(dummyCert, caCert, nil)
		
		req := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(reqReq))
		w := httptest.NewRecorder()
		s.HandleOCSP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}
		
		ocspResp, err := ocsp.ParseResponse(w.Body.Bytes(), caCert)
		if err != nil {
			t.Fatalf("failed to parse OCSP response: %v", err)
		}
		if ocspResp == nil {
			t.Fatal("parsed OCSP response is nil")
		}
		if ocspResp.Status != ocsp.Good {
			t.Errorf("expected status Good, got %d", ocspResp.Status)
		}
	})

	t.Run("GET Valid Request", func(t *testing.T) {
		dummyCert := &x509.Certificate{SerialNumber: big.NewInt(200)}
		reqReq, _ := ocsp.CreateRequest(dummyCert, caCert, nil)
		b64 := base64.StdEncoding.EncodeToString(reqReq)
		
		req := httptest.NewRequest(http.MethodGet, "/ocsp/"+b64, nil)
		w := httptest.NewRecorder()
		s.HandleOCSP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("Revoked Status", func(t *testing.T) {
		serial := big.NewInt(300)
		db.ReplaceBulkRevocations(ctx, caCert.Subject.CommonName, []*big.Int{serial})
		db.InvalidateCache(ctx)

		dummyCert := &x509.Certificate{SerialNumber: serial}
		reqReq, _ := ocsp.CreateRequest(dummyCert, caCert, nil)
		
		req := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(reqReq))
		w := httptest.NewRecorder()
		s.HandleOCSP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}

		ocspResp, err := ocsp.ParseResponse(w.Body.Bytes(), caCert)
		if err != nil {
			t.Fatalf("failed to parse OCSP response: %v", err)
		}
		if ocspResp == nil {
			t.Fatal("parsed OCSP response is nil")
		}
		if ocspResp.Status != ocsp.Revoked {
			t.Errorf("expected status Revoked, got %d", ocspResp.Status)
		}
	})

	t.Run("Unknown Issuer", func(t *testing.T) {
		otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		otherTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Other CA"},
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			BasicConstraintsValid: true,
			IsCA: true,
		}
		otherDER, _ := x509.CreateCertificate(rand.Reader, otherTemplate, otherTemplate, &otherKey.PublicKey, otherKey)
		otherCert, _ := x509.ParseCertificate(otherDER)

		dummyCert := &x509.Certificate{SerialNumber: big.NewInt(1)}
		reqReq, _ := ocsp.CreateRequest(dummyCert, otherCert, nil)
		
		req := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(reqReq))
		w := httptest.NewRecorder()
		s.HandleOCSP(w, req)

		if w.Header().Get("Content-Type") != "application/ocsp-response" {
			t.Errorf("expected content type application/ocsp-response, got %s", w.Header().Get("Content-Type"))
		}
		
		// ocsp.UnauthorizedErrorResponse is a valid OCSP response indicating Error
	})
}
