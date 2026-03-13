package database

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/redis/go-redis/v9"
)

type DB struct {
	client *redis.Client
}

func New(addr, password string) *DB {
	return &DB{
		client: redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: password,
		}),
	}
}

// ReplaceBulkRevocations replaces all revocation records for a CA using a Redis Set.
func (db *DB) ReplaceBulkRevocations(ctx context.Context, caName string, serials []*big.Int) error {
	key := fmt.Sprintf("ca:%s:revoked", caName)
	
	pipe := db.client.TxPipeline()
	pipe.Del(ctx, key)
	
	if len(serials) > 0 {
		var members []any
		for _, s := range serials {
			members = append(members, fmt.Sprintf("%x", s))
		}
		pipe.SAdd(ctx, key, members...)
	}
	
	_, err := pipe.Exec(ctx)
	return err
}

// IsRevoked checks if a serial is in the revoked set for a CA.
func (db *DB) IsRevoked(ctx context.Context, caName string, serial *big.Int) (bool, error) {
	key := fmt.Sprintf("ca:%s:revoked", caName)
	return db.client.SIsMember(ctx, key, fmt.Sprintf("%x", serial)).Result()
}

// GetCachedResponse retrieves a pre-computed OCSP response for a serial under a CA.
func (db *DB) GetCachedResponse(ctx context.Context, caName string, serial *big.Int) ([]byte, error) {
	key := fmt.Sprintf("ocsp:cache:%s:%x", caName, serial)
	return db.client.Get(ctx, key).Bytes()
}

// CacheResponse saves a computed OCSP response to Redis with a TTL.
func (db *DB) CacheResponse(ctx context.Context, caName string, serial *big.Int, response []byte, ttl time.Duration) error {
	key := fmt.Sprintf("ocsp:cache:%s:%x", caName, serial)
	return db.client.Set(ctx, key, response, ttl).Err()
}

// InvalidateCache wipes all dynamically cached OCSP responses atomically.
// Called when PKI data (CRLs or certificates) is reloaded.
func (db *DB) InvalidateCache(ctx context.Context) error {
	// Lua script that atomically scans and deletes matching keys in batches.
	script := redis.NewScript(`
		local cursor = "0"
		repeat
			local result = redis.call("SCAN", cursor, "MATCH", ARGV[1], "COUNT", 100)
			cursor = result[1]
			local keys = result[2]
			if #keys > 0 then
				redis.call("DEL", unpack(keys))
			end
		until cursor == "0"
		return 0
	`)
	return script.Run(ctx, db.client, nil, "ocsp:cache:*").Err()
}
