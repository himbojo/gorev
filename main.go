package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/himbojo/gorev/internal/database"
	"github.com/himbojo/gorev/internal/parser"
	"github.com/himbojo/gorev/internal/server"
	"github.com/himbojo/gorev/internal/watcher"
)

func main() {
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	redisPassword := os.Getenv("REDIS_PASSWORD")

	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "."
	}

	ocspEndpoints := parseEndpoints("ENDPOINTS_OCSP", "/ocsp")
	crlEndpoints := parseEndpoints("ENDPOINTS_CRL", "/crls")
	caEndpoints := parseEndpoints("ENDPOINTS_CA", "/cas")
	chainEndpoints := parseEndpoints("ENDPOINTS_CHAIN", "")

	log.Printf("Starting gorev")
	log.Printf("Redis Address: %s", redisAddr)
	log.Printf("Data Directory: %s", dataDir)
	log.Printf("OCSP Endpoints: %v", ocspEndpoints)
	log.Printf("CRL Endpoints: %v", crlEndpoints)
	log.Printf("CA Endpoints: %v", caEndpoints)
	log.Printf("Chain Endpoints: %v", chainEndpoints)

	db := database.New(redisAddr, redisPassword)
	srv := server.New(db, dataDir, ocspEndpoints)

	reload := func() {
		log.Println("Reloading certificates and CRLs from", dataDir)

		var caCerts []*x509.Certificate
		var respCerts []*x509.Certificate
		var respKeys []crypto.Signer

		var looseCerts []*x509.Certificate
		var looseKeys []crypto.Signer

		// Load CAs
		caDir := filepath.Join(dataDir, "cas")
		if caFiles, err := os.ReadDir(caDir); err == nil {
			for _, f := range caFiles {
				if f.IsDir() || !isValidExt(f.Name()) {
					continue
				}
				path := filepath.Join(caDir, f.Name())
				if cert, err := parser.LoadCA(path); err == nil {
					caCerts = append(caCerts, cert)
					log.Printf("Loaded CA cert: %s", f.Name())
				} else {
					log.Printf("Warning: failed to load CA cert %s: %v", f.Name(), err)
				}
			}
		}

		// Load Responders
		respDir := filepath.Join(dataDir, "responders")
		if respFiles, err := os.ReadDir(respDir); err == nil {
			for _, f := range respFiles {
				if f.IsDir() || !isValidExt(f.Name()) {
					continue
				}
				path := filepath.Join(respDir, f.Name())
				if key, err := parser.LoadPrivateKey(path); err == nil {
					looseKeys = append(looseKeys, key)
					log.Printf("Loaded responder key: %s", f.Name())
				} else if cert, err := parser.LoadCA(path); err == nil {
					looseCerts = append(looseCerts, cert)
					log.Printf("Loaded responder cert: %s", f.Name())
				}
			}
		}

		// Pair up loose certs and keys by public key to form responders
		for _, cert := range looseCerts {
			certPub, err1 := x509.MarshalPKIXPublicKey(cert.PublicKey)
			matched := false
			for _, key := range looseKeys {
				keyPub, err2 := x509.MarshalPKIXPublicKey(key.Public())
				if err1 == nil && err2 == nil && bytes.Equal(certPub, keyPub) {
					respCerts = append(respCerts, cert)
					respKeys = append(respKeys, key)
					matched = true
					log.Printf("Paired responder cert/key for %s", cert.Subject.CommonName)
					break
				}
			}
			if !matched {
				log.Printf("Warning: failed to pair responder cert: %s", cert.Subject.CommonName)
			}
		}

		if len(caCerts) == 0 {
			log.Println("WARNING: No CA certificates were loaded from data/cas/! The responder cannot function properly.")
		}
		if len(respCerts) == 0 {
			log.Println("WARNING: No valid responder certificates with matching private keys were loaded from data/responders/! It cannot sign OCSP responses.")
		}

		srv.UpdateCerts(caCerts, respCerts, respKeys)

		// Invalidate cache BEFORE loading new CRL data so stale cached responses
		// cannot be served while revocation sets are being updated. (L1 fix)
		if err := db.InvalidateCache(context.Background()); err != nil {
			log.Printf("Warning: failed to invalidate OCSP cache: %v", err)
		} else {
			log.Println("Successfully invalidated OCSP cache")
		}

		// Now load CRLs and update DB
		var loadedCRLs int
		crlDir := filepath.Join(dataDir, "crls")
		if crlFiles, err := os.ReadDir(crlDir); err == nil {
			for _, file := range crlFiles {
				if file.IsDir() || !strings.HasSuffix(strings.ToLower(file.Name()), ".crl") {
					continue
				}
				path := filepath.Join(crlDir, file.Name())
				crl, err := parser.LoadCRL(path)
				if err != nil {
					log.Printf("Failed to load CRL %s: %v", file.Name(), err)
					continue
				}

				crlIssuerCN := crl.Issuer.CommonName

				// Find the matching CA and verify the CRL signature (M2 fix)
				var matchedCA *x509.Certificate
				for _, ca := range caCerts {
					if ca.Subject.CommonName == crlIssuerCN {
						matchedCA = ca
						break
					}
				}

				if matchedCA != nil {
					if err := crl.CheckSignatureFrom(matchedCA); err != nil {
						log.Printf("WARNING: CRL %s failed signature verification against CA %s: %v", file.Name(), matchedCA.Subject.CommonName, err)
						continue
					}
				} else {
					log.Printf("WARNING: CRL %s has no matching CA for issuer %s — skipping (cannot verify signature)", file.Name(), crlIssuerCN)
					continue
				}

				caName := matchedCA.Subject.CommonName

				var revokedSerials []*big.Int
				for _, rev := range crl.RevokedCertificates {
					revokedSerials = append(revokedSerials, rev.SerialNumber)
				}

				err = db.ReplaceBulkRevocations(context.Background(), caName, revokedSerials)
				if err != nil {
					log.Printf("Failed to update database for CRL %s: %v", file.Name(), err)
				} else {
					log.Printf("Loaded CRL %s with %d revoked certs for CA %s (signature verified)", file.Name(), len(revokedSerials), caName)
					loadedCRLs++
				}
			}
		} // Close if crlFiles

		if loadedCRLs == 0 {
			log.Println("WARNING: No CRLs were loaded! The responder will not know of any revocations.")
		}
	} // Close reload func

	reload()

	w, err := watcher.New(dataDir, reload)
	if err != nil {
		log.Fatalf("Failed to start file watcher: %v", err)
	}
	defer w.Close()

	// Register OCSP endpoints
	ocspRegistered := make(map[string]bool)
	for _, ep := range ocspEndpoints {
		if !ocspRegistered[ep] {
			http.HandleFunc(ep, srv.HandleOCSP)
			ocspRegistered[ep] = true
		}
		route := ep
		if !strings.HasSuffix(route, "/") {
			route += "/"
		}
		if !ocspRegistered[route] {
			http.HandleFunc(route, srv.HandleOCSP)
			ocspRegistered[route] = true
		}
	}

	// Collect file-serving directories per route to handle overlapping paths.
	// Multiple service types (CRL, CA, Chain) can share the same URL path.
	routeDirs := make(map[string][]string)

	crlDir := filepath.Join(dataDir, "crls")
	caDir := filepath.Join(dataDir, "cas")

	for _, ep := range crlEndpoints {
		route := ep
		if !strings.HasSuffix(route, "/") {
			route += "/"
		}
		routeDirs[route] = append(routeDirs[route], crlDir)
	}
	for _, ep := range caEndpoints {
		route := ep
		if !strings.HasSuffix(route, "/") {
			route += "/"
		}
		routeDirs[route] = append(routeDirs[route], caDir)
	}
	for _, ep := range chainEndpoints {
		route := ep
		if !strings.HasSuffix(route, "/") {
			route += "/"
		}
		routeDirs[route] = append(routeDirs[route], caDir)
	}

	// Deduplicate directories per route and register handlers
	for route, dirs := range routeDirs {
		seen := make(map[string]bool)
		var unique []string
		for _, d := range dirs {
			if !seen[d] {
				seen[d] = true
				unique = append(unique, d)
			}
		}
		http.Handle(route, &multiDirHandler{prefix: route, dirs: unique})
	}

	port := "8080"
	httpServer := &http.Server{Addr: ":" + port}

	// Graceful shutdown on SIGTERM/SIGINT (I1 fix)
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		sig := <-sigCh
		log.Printf("Received signal %v, shutting down gracefully...", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("Graceful shutdown failed: %v", err)
		}
	}()

	log.Printf("Listening on :%s", port)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
	log.Println("Server stopped")
}

// multiDirHandler serves files from multiple directories on a single route.
// It tries each directory in order and serves the first match found.
type multiDirHandler struct {
	prefix string
	dirs   []string
}

func (h *multiDirHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, h.prefix)
	if name == "" {
		http.NotFound(w, r)
		return
	}

	for _, dir := range h.dirs {
		cleaned := filepath.Clean("/" + name)
		fullPath := filepath.Join(dir, cleaned)

		// Resolve symlinks and verify the real path is within the allowed directory. (H1 fix)
		resolved, err := filepath.EvalSymlinks(fullPath)
		if err != nil {
			continue // file doesn't exist or can't be resolved
		}
		absDir, err := filepath.Abs(dir)
		if err != nil {
			log.Printf("Warning: failed to get absolute path for %s: %v", dir, err)
			continue
		}
		if !strings.HasPrefix(resolved, absDir+string(os.PathSeparator)) && resolved != absDir {
			log.Printf("Blocked path traversal attempt: %s resolved to %s (outside %s)", r.URL.Path, resolved, absDir)
			http.NotFound(w, r)
			return
		}

		if info, err := os.Stat(resolved); err == nil && !info.IsDir() {
			http.ServeFile(w, r, resolved)
			return
		}
	}
	http.NotFound(w, r)
}

// parseEndpoints reads a comma-separated list of URL paths from the given
// environment variable. If the variable is unset or empty, fallback is used.
// An empty fallback means the endpoint type is disabled by default.
func parseEndpoints(envVar, fallback string) []string {
	raw := os.Getenv(envVar)
	if raw == "" {
		if fallback == "" {
			return nil
		}
		raw = fallback
	}

	parts := strings.Split(raw, ",")
	var endpoints []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		endpoints = append(endpoints, p)
	}
	return endpoints
}

// isValidExt checks if a file extension is commonly used for certificates or keys.
func isValidExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".pem", ".crt", ".cer", ".der", ".key":
		return true
	}
	return false
}
