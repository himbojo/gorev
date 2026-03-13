package database

import (
	"context"
	"fmt"
	"math/big"

	"github.com/redis/go-redis/v9"
)

type DB struct {
	client *redis.Client
}

func New(addr string) *DB {
	return &DB{
		client: redis.NewClient(&redis.Options{
			Addr: addr,
		}),
	}
}

// ReplaceBulkRevocations replaces all revocation records for a CA using a Redis Set.
func (db *DB) ReplaceBulkRevocations(ctx context.Context, caName string, serials []*big.Int) error {
	key := fmt.Sprintf("ca:%s:revoked", caName)
	
	pipe := db.client.TxPipeline()
	pipe.Del(ctx, key)
	
	if len(serials) > 0 {
		var members []interface{}
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
