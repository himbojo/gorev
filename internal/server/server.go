package server

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/himbojo/gorev/internal/database"
	"golang.org/x/crypto/ocsp"
)

type Server struct {
	db           *database.DB
	dataDir      string
	ocspPrefixes []string
	mu           sync.RWMutex
	caCerts      []*x509.Certificate
	respCerts    []*x509.Certificate
	respKeys     []crypto.Signer
}

func New(db *database.DB, dataDir string, ocspPrefixes []string) *Server {
	return &Server{
		db:           db,
		dataDir:      dataDir,
		ocspPrefixes: ocspPrefixes,
	}
}

func (s *Server) UpdateCerts(caCerts []*x509.Certificate, respCerts []*x509.Certificate, respKeys []crypto.Signer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.caCerts = caCerts
	s.respCerts = respCerts
	s.respKeys = respKeys
}

func (s *Server) getCerts() ([]*x509.Certificate, []*x509.Certificate, []crypto.Signer) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]*x509.Certificate(nil), s.caCerts...),
		append([]*x509.Certificate(nil), s.respCerts...),
		append([]crypto.Signer(nil), s.respKeys...)
}

func (s *Server) HandleOCSP(w http.ResponseWriter, r *http.Request) {
	var reqBytes []byte
	var err error

	switch r.Method {
	case http.MethodPost:
		reqBytes, err = io.ReadAll(io.LimitReader(r.Body, 64*1024))
	case http.MethodGet:
		b64 := r.URL.Path
		for _, pfx := range s.ocspPrefixes {
			p := pfx
			if !strings.HasSuffix(p, "/") {
				p += "/"
			}
			if len(b64) > len(p) && b64[:len(p)] == p {
				b64 = b64[len(p):]
				break
			}
		}
		reqBytes, err = base64.StdEncoding.DecodeString(b64)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil || len(reqBytes) == 0 {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	ocspReq, err := ocsp.ParseRequest(reqBytes)
	if err != nil {
		log.Printf("Failed to parse OCSP request: %v", err)
		http.Error(w, "Bad OCSP Request", http.StatusBadRequest)
		return
	}

	caCerts, respCerts, respKeys := s.getCerts()
	if len(respCerts) == 0 || len(respKeys) == 0 {
		http.Error(w, "Responder not ready", http.StatusInternalServerError)
		return
	}

	var issuer *x509.Certificate
	var issuerName string
	for _, ca := range caCerts {
		if isIssuerMatch(ca, ocspReq) {
			issuer = ca
			issuerName = ca.Subject.CommonName
			break
		}
	}

	if issuer == nil {
		log.Printf("OCSP request from unknown issuer — no matching CA found")
		// Return OCSP Unauthorized per RFC 6960 §2.3
		w.Header().Set("Content-Type", "application/ocsp-response")
		if _, err := w.Write(ocsp.UnauthorizedErrorResponse); err != nil { // G104: handle write error
			log.Printf("Warning: failed to write OCSP unauthorized response: %v", err)
		}
		return
	}

	var responderCert *x509.Certificate
	var responderKey crypto.Signer

	for i, rc := range respCerts {
		if rc.Issuer.String() == issuer.Subject.String() {
			if err := rc.CheckSignatureFrom(issuer); err == nil {
				responderCert = rc
				responderKey = respKeys[i]
				break
			}
		}
		if bytes.Equal(rc.Raw, issuer.Raw) {
			responderCert = rc
			responderKey = respKeys[i]
			break
		}
	}

	if responderCert == nil {
		log.Printf("No matching responder cert found for issuer %s", issuerName)
		http.Error(w, "No matching responder cert found", http.StatusInternalServerError)
		return
	}

	// Check cache first
	cachedResp, err := s.db.GetCachedResponse(r.Context(), issuerName, ocspReq.SerialNumber)
	if err == nil && len(cachedResp) > 0 {
		w.Header().Set("Content-Type", "application/ocsp-response")
		if _, err := w.Write(cachedResp); err != nil { // #nosec G705 -- cachedResp is binary DER-encoded OCSP data from trusted Redis cache, not user-controlled HTML
			log.Printf("Warning: failed to write cached OCSP response: %v", err)
		}
		return
	}

	isRevoked, err := s.db.IsRevoked(r.Context(), issuerName, ocspReq.SerialNumber)
	if err != nil {
		log.Printf("DB error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	status := ocsp.Good
	if isRevoked {
		status = ocsp.Revoked
	}

	template := ocsp.Response{
		Status:       status,
		SerialNumber: ocspReq.SerialNumber,
		ThisUpdate:   time.Now().Truncate(time.Minute),
		NextUpdate:   time.Now().Add(24 * time.Hour).Truncate(time.Minute),
		Certificate:  responderCert,
	}
	if isRevoked {
		template.RevokedAt = time.Now().Truncate(time.Minute)
		template.RevocationReason = ocsp.Unspecified
	}

	respBytes, err := ocsp.CreateResponse(issuer, responderCert, template, responderKey)
	if err != nil {
		log.Printf("Failed to create OCSP response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Cache the response
	ttl := time.Until(template.NextUpdate)
	if ttl <= 0 {
		ttl = 5 * time.Minute // Fallback TTL if NextUpdate is in the past or missing
	}
	err = s.db.CacheResponse(r.Context(), issuerName, ocspReq.SerialNumber, respBytes, ttl)
	if err != nil {
		log.Printf("Warning: failed to cache OCSP response: %v", err)
	}

	w.Header().Set("Content-Type", "application/ocsp-response")
	if _, err := w.Write(respBytes); err != nil {
		log.Printf("Warning: failed to write OCSP response: %v", err)
	}
}

func isIssuerMatch(issuer *x509.Certificate, req *ocsp.Request) bool {
	hashAlgo := req.HashAlgorithm
	if !hashAlgo.Available() {
		return false
	}
	h := hashAlgo.New()
	h.Write(issuer.RawSubject)
	nameHash := h.Sum(nil)

	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return false
	}
	h.Reset()
	h.Write(spki.PublicKey.RightAlign())
	keyHash := h.Sum(nil)

	return bytes.Equal(nameHash, req.IssuerNameHash) && bytes.Equal(keyHash, req.IssuerKeyHash)
}
