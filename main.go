package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"

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

	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "."
	}

	ocspEndpoints := parseEndpoints("ENDPOINTS_OCSP", "/ocsp")
	crlEndpoints := parseEndpoints("ENDPOINTS_CRL", "/crls")
	caEndpoints := parseEndpoints("ENDPOINTS_CA", "/cas")
	chainEndpoints := parseEndpoints("ENDPOINTS_CHAIN", "")

	fmt.Printf("Starting gorev\n")
	fmt.Printf("Redis Address: %s\n", redisAddr)
	fmt.Printf("Data Directory: %s\n", dataDir)
	fmt.Printf("OCSP Endpoints: %v\n", ocspEndpoints)
	fmt.Printf("CRL Endpoints: %v\n", crlEndpoints)
	fmt.Printf("CA Endpoints: %v\n", caEndpoints)
	fmt.Printf("Chain Endpoints: %v\n", chainEndpoints)

	db := database.New(redisAddr)
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
				if f.IsDir() || !strings.HasSuffix(strings.ToLower(f.Name()), ".pem") {
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
				if f.IsDir() || !strings.HasSuffix(strings.ToLower(f.Name()), ".pem") {
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

		srv.UpdateCerts(caCerts, respCerts, respKeys)

		// Now load CRLs and update DB
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

			var caName string
			for _, ca := range caCerts {
				if ca.Subject.CommonName == crlIssuerCN {
					caName = ca.Subject.CommonName
					break
				}
			}
			if caName == "" {
				caName = crlIssuerCN
			}

			var revokedSerials []*big.Int
			for _, rev := range crl.RevokedCertificates {
				revokedSerials = append(revokedSerials, rev.SerialNumber)
			}

			err = db.ReplaceBulkRevocations(context.Background(), caName, revokedSerials)
			if err != nil {
				log.Printf("Failed to update database for CRL %s: %v", file.Name(), err)
			} else {
				log.Printf("Loaded CRL %s with %d revoked certs for CA %s", file.Name(), len(revokedSerials), caName)
			}
		}
		} // Close if crlFiles

		// Ensure cache is wiped so no old revocations are served
		if err := db.InvalidateCache(context.Background()); err != nil {
			log.Printf("Warning: failed to invalidate OCSP cache: %v", err)
		} else {
			log.Println("Successfully invalidated OCSP cache")
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
	fmt.Printf("Listening on :%s\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
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
		fullPath := filepath.Join(dir, filepath.Clean("/"+name))
		if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
			http.ServeFile(w, r, fullPath)
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
