package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg := LoadConfig()

	log.Printf("Starting gorev")
	log.Printf("Redis Address: %s", cfg.RedisAddr)
	log.Printf("Data Directory: %s", cfg.DataDir)
	log.Printf("OCSP Endpoints: %v", cfg.OCSPEndpoints)
	log.Printf("CRL Endpoints: %v", cfg.CRLEndpoints)
	log.Printf("CA Endpoints: %v", cfg.CAEndpoints)
	log.Printf("Chain Endpoints: %v", cfg.ChainEndpoints)

	app, err := NewApp(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize application: %v", err)
	}
	defer app.Watcher.Close()

	// Perform the initial load of certificates and CRLs
	app.ReloadPKI()

	mux := app.SetupRoutes()

	port := "8080"
	httpServer := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	// Graceful shutdown on SIGTERM/SIGINT
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
