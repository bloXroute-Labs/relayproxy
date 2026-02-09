package common

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	consensusspec "github.com/attestantio/go-eth2-client/spec"
	consensusbellatrix "github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	gocache "github.com/patrickmn/go-cache"
)

const (
	// TxSigMaxSize is the max size of the RLP encoded tx signature (v 1 byte, s,r 32 bytes each with a leading rlp length prefix)
	TxSigMaxSize = 67

	// MaxBlobsPerBlockFulu is the maximum number of blobs allowed per block in Fulu
	// This can be configured based on network requirements
	// MaxBlobsPerBlockFulu = 21 // Disabled for now, see usage below

	TxHashKeySize = 8
)

// -----------------------------------------------------------------------------------------------------------------------------------------
// CachingHydrator handles hydration of block submissions with per-builder caching
type CachingHydrator struct {
	cache *HydrationCache
}

// NewCachingHydrator creates a new hydrator with the provided cache
func NewCachingHydrator(cache *HydrationCache) *CachingHydrator {
	return &CachingHydrator{
		cache: cache,
	}
}

// HydratedData contains the result of hydration
type HydratedData struct {
	TxCacheWrites     int
	TxCacheHits       int
	TxCacheBuilders   int // Number of builders with cached transactions
	TxCacheTotalSize  int // Total transactions across all builders
	TxCacheTotalBytes int // Total bytes of transactions across all builders
	BlobCacheWrites   int
	BlobCacheHits     int
	BlobCacheSize     int
}

// Hydrate hydrates a versioned block submission using FxHash
func (h *CachingHydrator) Hydrate(request *VersionedExtendedSubmitBlockRequest) (*HydratedData, error) {
	switch request.Version {
	case consensusspec.DataVersionFulu:
		return h.hydrateFulu(request.Fulu)
	default:
		return nil, fmt.Errorf("unsupported version: %s", request.Version.String())
	}
}

// hydrateFulu hydrates a Fulu submission using explicit new_items from extended bundle
// In Fulu: commitment is the cache key, proofs array is stored with each blob
func (h *CachingHydrator) hydrateFulu(request *FuluExtendedSubmitBlockRequest) (*HydratedData, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}
	if request.Message == nil {
		return nil, fmt.Errorf("nil message")
	}
	if request.ExecutionPayload == nil {
		return nil, fmt.Errorf("nil execution payload")
	}
	if request.BlobsBundle == nil {
		return nil, fmt.Errorf("nil blobs bundle")
	}

	builderPubKey := request.Message.BuilderPubkey
	txCacheHits := 0
	txCacheWrites := 0
	txCacheBuilders := 0
	txCacheTotalSize := 0
	txCacheTotalBytes := 0
	blobCacheHits := 0
	blobCacheWrites := 0
	blobCacheSize := 0
	var lastError error

	if d, err := h.HydrateFuluTransactions(builderPubKey, request.ExecutionPayload); err != nil {
		lastError = fmt.Errorf("failed to hydrate transactions: %w", err)
	} else {
		txCacheWrites = d.CacheWrites
		txCacheHits = d.CacheHits
		txCacheBuilders = d.CacheBuilders
		txCacheTotalSize = d.CacheTotalSize
		txCacheTotalBytes = d.CacheTotalBytes
	}

	if d, err := h.HydrateFuluBlobs(request.BlobsBundle); err != nil {
		lastError = fmt.Errorf("failed to hydrate blobs: %w", err)
	} else {
		blobCacheWrites = d.CacheWrites
		blobCacheHits = d.CacheHits
		blobCacheSize = d.CacheSize
	}

	// Return last error if any occurred during hydration
	if lastError != nil {
		return nil, lastError
	}

	return &HydratedData{
		TxCacheWrites:     txCacheWrites,
		TxCacheHits:       txCacheHits,
		TxCacheBuilders:   txCacheBuilders,
		TxCacheTotalSize:  txCacheTotalSize,
		TxCacheTotalBytes: txCacheTotalBytes,
		BlobCacheWrites:   blobCacheWrites,
		BlobCacheHits:     blobCacheHits,
		BlobCacheSize:     blobCacheSize,
	}, nil
}

type TransactionsHydrateData struct {
	CacheWrites     int
	CacheHits       int
	CacheBuilders   int // Number of builders with cached transactions
	CacheTotalSize  int // Total transactions across all builders
	CacheTotalBytes int // Total bytes of transactions across all builders
}

func (h *CachingHydrator) HydrateFuluTransactions(builderPubkey phase0.BLSPubKey, payload *deneb.ExecutionPayload) (*TransactionsHydrateData, error) {
	txCache := h.cache.getTxCache(builderPubkey)

	cacheHits := 0
	cacheWrites := 0
	var lastError error

	// Hydrate transactions (per-builder cache)
	// Continue processing all transactions even on error to maximize cache population
	for i, tx := range payload.Transactions {
		if len(tx) == TxHashKeySize {
			// This is a hashed transaction, hydrate it
			hash := binary.LittleEndian.Uint64(tx)
			key := txHashKey(hash)

			if cachedObj, found := txCache.Get(key); found {
				cachedTx := cachedObj.([]byte)
				payload.Transactions[i] = cachedTx
				cacheHits++
			} else {
				lastError = fmt.Errorf("unknown tx: index %d, hash %d", i, hash)
				// Continue processing to populate cache with subsequent items
			}
		} else {
			// This is a full transaction, add it to per-builder cache
			if len(tx) < TxSigMaxSize {
				return nil, fmt.Errorf("invalid tx bytes: length %d, index %d", len(tx), i)
			}

			hash := hashTransaction(tx)
			key := txHashKey(hash)
			txCopy := make([]byte, len(tx))
			copy(txCopy, tx)
			txCache.Set(key, txCopy, gocache.DefaultExpiration)
			cacheWrites++
		}
	}

	if lastError != nil {
		return nil, lastError
	}

	builders, totalSize, totalBytes := h.cache.getTxCacheStats()
	return &TransactionsHydrateData{
		CacheWrites:     cacheWrites,
		CacheHits:       cacheHits,
		CacheBuilders:   builders,
		CacheTotalSize:  totalSize,
		CacheTotalBytes: totalBytes,
	}, nil
}

type BlobsHydrateData struct {
	CacheWrites int
	CacheHits   int
	CacheSize   int
}

func (h *CachingHydrator) HydrateFuluBlobs(blobsBundle *FuluExtendedBlobsBundle) (*BlobsHydrateData, error) {
	blobCache := h.cache.getBlobCache()

	cacheHits := 0
	cacheWrites := 0
	var lastError error

	// Cache new blob items in shared blob cache
	// Store pointers to avoid copying 128KB blobs during cache population
	newBlobCount := len(blobsBundle.NewItems)
	for i := range blobsBundle.NewItems {
		key := blobFuluKey(blobsBundle.NewItems[i].Commitment)
		blobCache.Set(key, blobsBundle.NewItems[i], gocache.DefaultExpiration)
		cacheWrites++
	}

	// Check blob count using request.BlobsBundle.Commitments array
	// TODO: decide if we want to enforce this limit (will require querying chain spec per epoch)
	// if len(blobsBundle.Commitments) > MaxBlobsPerBlockFulu {
	// 	return nil, fmt.Errorf("too many blobs: %d, max %d", len(blobsBundle.Commitments), MaxBlobsPerBlockFulu)
	// }

	// Hydrate blobs from shared blob cache (content-addressable by commitment)
	// Continue processing all blobs even on error to maximize cache population
	blobsBundle.Proofs = make([]deneb.KZGProof, 0, len(blobsBundle.Commitments)*maxProofsPerBlob)
	blobsBundle.Blobs = make([]deneb.Blob, len(blobsBundle.Commitments))

	for i, commitment := range blobsBundle.Commitments {
		key := blobFuluKey(commitment)
		if cachedObj, found := blobCache.Get(key); found {
			item := cachedObj.(*FuluHydrationBlobItem)
			blobsBundle.Proofs = append(blobsBundle.Proofs, item.Proof...)
			blobsBundle.Blobs[i] = item.Blob
			cacheHits++
		} else {
			lastError = fmt.Errorf("unknown blob (Fulu): index %d", i)
			// Continue processing to populate cache with subsequent items
		}
	}

	if lastError != nil {
		return nil, lastError
	}

	cacheHits -= newBlobCount
	return &BlobsHydrateData{
		CacheHits:   cacheHits,
		CacheWrites: cacheWrites,
		CacheSize:   blobCache.ItemCount(),
	}, nil
}

// Helper functions to convert various types to string keys for go-cache
func txHashKey(hash uint64) string {
	return fmt.Sprintf("tx-fulu:%016x", hash)
}

func blobFuluKey(commitment deneb.KZGCommitment) string {
	return fmt.Sprintf("blob-fulu:%s", hex.EncodeToString(commitment[:]))
}

// hashTransaction hashes the last TxSigMaxSize bytes of a transaction using FxHash
func hashTransaction(tx consensusbellatrix.Transaction) uint64 {
	if len(tx) < TxSigMaxSize {
		return 0
	}

	// Get the last 67 bytes (transaction signature)
	bytes := tx[len(tx)-TxSigMaxSize:]

	// Use FxHash (Rust-compatible)
	return FxHash64(bytes)
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// HydrationCache manages per-builder transaction caches and a shared blob cache
// Transaction caches are isolated per builder for security
// Blob cache is shared globally since blobs are content-addressable by KZG commitment
type HydrationCache struct {
	txCaches  sync.Map       // map[string]*gocache.Cache, keyed by builder pubkey hex (for transactions)
	blobCache *gocache.Cache // shared cache for all blobs (content-addressable by commitment)
}

// NewHydrationCache creates a new hydration cache
func NewHydrationCache() *HydrationCache {
	return &HydrationCache{
		blobCache: gocache.New(30*time.Second, 30*time.Second),
	}
}

// getTxCache returns the transaction cache for a builder, creating it if necessary
func (hc *HydrationCache) getTxCache(builderPubKey phase0.BLSPubKey) *gocache.Cache {
	key := builderPubKeyToString(builderPubKey)

	// Try to load existing cache
	if val, ok := hc.txCaches.Load(key); ok {
		return val.(*gocache.Cache)
	}

	// Create new cache
	cache := gocache.New(30*time.Second, 30*time.Second) // Leaving it for several slots

	// Store it (LoadOrStore handles race condition)
	actual, _ := hc.txCaches.LoadOrStore(key, cache)
	return actual.(*gocache.Cache)
}

// getTxCacheStats returns the number of builder keys, total transaction count, and total bytes across all builders
func (hc *HydrationCache) getTxCacheStats() (builders int, totalTxs int, totalBytes int) {
	hc.txCaches.Range(func(key, value any) bool {
		builders++
		if cache, ok := value.(*gocache.Cache); ok {
			for _, item := range cache.Items() {
				if tx, ok := item.Object.([]byte); ok {
					totalTxs++
					totalBytes += len(tx)
				}
			}
		}
		return true
	})
	return builders, totalTxs, totalBytes
}

// getBlobCache returns the shared blob cache
func (hc *HydrationCache) getBlobCache() *gocache.Cache {
	return hc.blobCache
}

// builderPubKeyToString converts a BLS public key to a string for use as a map key
func builderPubKeyToString(pubKey phase0.BLSPubKey) string {
	return hex.EncodeToString(pubKey[:])
}
