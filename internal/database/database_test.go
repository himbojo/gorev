package database

import (
	"context"
	"math/big"
	"os"
	"testing"
	"time"
)

func TestDatabase(t *testing.T) {
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	
	// Skip if Redis is not available
	// In a real CI environment, we'd ensure Redis is running or use a mock.
	// Since stress_test.go relies on local Redis, we'll do the same but with a timeout check.
	// Actually, let's just try to connect and skip if it fails.
	
	db := New(redisAddr, os.Getenv("REDIS_PASSWORD"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	if err := db.client.Ping(ctx).Err(); err != nil {
		t.Skipf("Redis not available at %s, skipping database tests: %v", redisAddr, err)
	}

	caName := "TestCA"
	serials := []*big.Int{big.NewInt(123), big.NewInt(456)}

	t.Run("ReplaceBulkRevocations", func(t *testing.T) {
		err := db.ReplaceBulkRevocations(ctx, caName, serials)
		if err != nil {
			t.Fatalf("ReplaceBulkRevocations failed: %v", err)
		}

		revoked, err := db.IsRevoked(ctx, caName, big.NewInt(123))
		if err != nil || !revoked {
			t.Errorf("expected serial 123 to be revoked, got %v (err: %v)", revoked, err)
		}

		revoked, err = db.IsRevoked(ctx, caName, big.NewInt(789))
		if err != nil || revoked {
			t.Errorf("expected serial 789 to not be revoked, got %v (err: %v)", revoked, err)
		}
	})

	t.Run("CacheResponse", func(t *testing.T) {
		serial := big.NewInt(123)
		resp := []byte("fake-ocsp-response")
		ttl := 10 * time.Minute

		err := db.CacheResponse(ctx, caName, serial, resp, ttl)
		if err != nil {
			t.Fatalf("CacheResponse failed: %v", err)
		}

		cached, err := db.GetCachedResponse(ctx, caName, serial)
		if err != nil {
			t.Fatalf("GetCachedResponse failed: %v", err)
		}
		if string(cached) != string(resp) {
			t.Errorf("expected cached response %s, got %s", resp, cached)
		}
	})

	t.Run("InvalidateCache", func(t *testing.T) {
		serial := big.NewInt(123)
		resp := []byte("fake-ocsp-response")
		db.CacheResponse(ctx, caName, serial, resp, 10*time.Minute)

		err := db.InvalidateCache(ctx)
		if err != nil {
			t.Fatalf("InvalidateCache failed: %v", err)
		}

		_, err = db.GetCachedResponse(ctx, caName, serial)
		if err == nil {
			t.Error("expected cache miss after invalidation, but found entry")
		}
	})
}
