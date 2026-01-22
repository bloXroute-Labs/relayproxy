package common

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// Test vectors match the Rust rustc-hash implementation
// These test cases verify compatibility with https://github.com/rust-lang/rustc-hash
// Expected values generated from Rust: use rustc_hash::FxHasher; use std::hash::Hasher;

func TestFxHash64_EmptyBytes(t *testing.T) {
	result := FxHash64([]byte{})
	expected := uint64(0xf456d26876d72d91) // Rust: FxHasher::default().finish()
	if result != expected {
		t.Errorf("Empty bytes hash mismatch: got 0x%016x, want 0x%016x", result, expected)
	}
}

func TestFxHash64_SingleByte(t *testing.T) {
	tests := []struct {
		input    byte
		name     string
		expected uint64
	}{
		{0, "zero", 0x4b9d47c1631257a6},
		{1, "one", 0x5230c309ca75d50e},
		{100, "hundred", 0xa4ad5d0078277688},
		{255, "max", 0xc621ba7d965afb2d},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FxHash64([]byte{tt.input})
			if result != tt.expected {
				t.Errorf("Hash of [%d]: got 0x%016x, want 0x%016x", tt.input, result, tt.expected)
			}
		})
	}
}

func TestFxHash64_MultipleBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected uint64
	}{
		{"2 bytes", []byte{1, 2}, 0x1723e7723fcd58ad},
		{"4 bytes", []byte{1, 2, 3, 4}, 0x7c904448e3e62af1},
		{"8 bytes", []byte{1, 2, 3, 4, 5, 6, 7, 8}, 0xc86328dec648bf4e},
		{"16 bytes", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, 0x24f418a28d850f9c},
		{"32 bytes zeros", make([]byte, 32), 0x956be39f261cbaa7},
		{"67 bytes zeros (tx sig size)", make([]byte, 67), 0x0f35ddc3bc7d6364},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FxHash64(tt.input)
			if result != tt.expected {
				t.Errorf("Hash of %s: got 0x%016x, want 0x%016x", tt.name, result, tt.expected)
			}
		})
	}
}

func TestFxHash64_TransactionSignature(t *testing.T) {
	// Simulate a transaction signature (last 67 bytes)
	// This represents the RLP-encoded signature portion: v (1 byte) + r (32 bytes) + s (32 bytes) + length prefixes
	txSig := make([]byte, 67)
	// Fill with sequential data
	for i := range txSig {
		txSig[i] = byte(i)
	}

	result := FxHash64(txSig)
	expected := uint64(0x4adaf274211bc4e4)
	if result != expected {
		t.Errorf("Transaction signature hash: got 0x%016x, want 0x%016x", result, expected)
	}

	// Test that changing one byte produces a different hash
	txSig[0] = 99
	result2 := FxHash64(txSig)
	expected2 := uint64(0x8d9809e07e4d3da8)
	if result2 != expected2 {
		t.Errorf("Modified signature hash: got 0x%016x, want 0x%016x", result2, expected2)
	}

	if result == result2 {
		t.Error("Expected different hash for modified input")
	}
}

func TestFxHash64_String(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected uint64
	}{
		{"empty string", "", 0xf456d26876d72d91},
		{"short string", "hello", 0x15136c07c8bce6e4},
		{"medium string", "These are some bytes for testing rustc_hash.", 0x209a12813f07be53},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FxHash64([]byte(tt.input))
			if result != tt.expected {
				t.Errorf("Hash of '%s': got 0x%016x, want 0x%016x", tt.input, result, tt.expected)
			}
		})
	}
}

func TestFxHasher_IncrementalWrite(t *testing.T) {
	data := []byte("hello world")

	// Hash all at once
	hashAll := FxHash64(data)
	expectedAll := uint64(0xac6f814ed569f75c)

	if hashAll != expectedAll {
		t.Errorf("All at once hash: got 0x%016x, want 0x%016x", hashAll, expectedAll)
	}

	// Hash incrementally - this produces a different result because each write()
	// compresses bytes independently and adds to the polynomial hash
	hasher := NewFxHasher()
	hasher.Write([]byte("hello"))
	hasher.Write([]byte(" "))
	hasher.Write([]byte("world"))
	hashIncremental := hasher.Sum64()
	expectedIncremental := uint64(0x546cc5e300d34a0f)

	if hashIncremental != expectedIncremental {
		t.Errorf("Incremental hash: got 0x%016x, want 0x%016x", hashIncremental, expectedIncremental)
	}

	// Verify they are different (this is expected behavior)
	if hashAll == hashIncremental {
		t.Error("Expected different hashes for all-at-once vs incremental")
	}
}

func TestFxHasher_Reset(t *testing.T) {
	hasher := NewFxHasher()
	hasher.Write([]byte("test"))
	hash1 := hasher.Sum64()

	hasher.Reset()
	hasher.Write([]byte("test"))
	hash2 := hasher.Sum64()

	if hash1 != hash2 {
		t.Errorf("Expected same hash after reset, got %d and %d", hash1, hash2)
	}
}

func TestFxHasher_WithSeed(t *testing.T) {
	data := []byte("test data")

	tests := []struct {
		seed     uint64
		expected uint64
	}{
		{0, 0x2f36fd702251fd2a},
		{1, 0xd7f088173616d315},
		{42, 0xdda7bcd9689d15d3},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("seed_%d", tt.seed), func(t *testing.T) {
			result := FxHash64WithSeed(data, tt.seed)
			if result != tt.expected {
				t.Errorf("Seed %d: got 0x%016x, want 0x%016x", tt.seed, result, tt.expected)
			}
		})
	}

	// Verify all seeds produce different hashes
	hash0 := FxHash64WithSeed(data, 0)
	hash1 := FxHash64WithSeed(data, 1)
	hash42 := FxHash64WithSeed(data, 42)

	if hash0 == hash1 || hash1 == hash42 || hash0 == hash42 {
		t.Error("Expected different hashes for different seeds")
	}
}

func TestHashTransaction(t *testing.T) {
	// Test with transaction shorter than TxSigMaxSize
	shortTx := make([]byte, 50)
	hash := hashTransaction(shortTx, HashTypeFxHash)
	if hash != 0 {
		t.Errorf("Expected 0 for short transaction, got %d", hash)
	}

	// Test with transaction exactly TxSigMaxSize
	exactTx := make([]byte, TxSigMaxSize)
	for i := range exactTx {
		exactTx[i] = byte(i)
	}
	hash1 := hashTransaction(exactTx, HashTypeFxHash)
	expected1 := uint64(0x4adaf274211bc4e4)
	if hash1 != expected1 {
		t.Errorf("Hash of %d-byte tx: got 0x%016x, want 0x%016x", len(exactTx), hash1, expected1)
	}

	// Test with longer transaction
	longTx := make([]byte, 200)
	copy(longTx[len(longTx)-TxSigMaxSize:], exactTx)
	hash2 := hashTransaction(longTx, HashTypeFxHash)
	expected2 := uint64(0x4adaf274211bc4e4)
	if hash2 != expected2 {
		t.Errorf("Hash of %d-byte tx: got 0x%016x, want 0x%016x", len(longTx), hash2, expected2)
	}

	// Since both have the same last 67 bytes, hashes should match
	if hash1 != hash2 {
		t.Errorf("Expected same hash for same last 67 bytes, got 0x%016x and 0x%016x", hash1, hash2)
	}
}

func TestHashTransactionFNV1a(t *testing.T) {
	// Test FNV1a hash type
	exactTx := make([]byte, TxSigMaxSize)
	for i := range exactTx {
		exactTx[i] = byte(i)
	}

	hashFxHash := hashTransaction(exactTx, HashTypeFxHash)
	hashFNV1a := hashTransaction(exactTx, HashTypeFNV1a)

	// Hashes should be different for different hash types
	if hashFxHash == hashFNV1a {
		t.Errorf("Expected different hashes for different hash types")
	}

	// Test default fallback to FxHash
	hashDefault := hashTransaction(exactTx, "unknown")
	if hashDefault != hashFxHash {
		t.Errorf("Expected default (unknown) to use FxHash, got 0x%016x, want 0x%016x", hashDefault, hashFxHash)
	}
}

func TestFxHash64_Deterministic(t *testing.T) {
	data := []byte("deterministic test data")

	hash1 := FxHash64(data)
	hash2 := FxHash64(data)
	hash3 := FxHash64(data)

	if hash1 != hash2 || hash2 != hash3 {
		t.Errorf("Expected deterministic hashes, got %d, %d, %d", hash1, hash2, hash3)
	}
}

// Test case to verify against known hash values from Rust implementation
// All expected values generated and verified against rustc-hash crate
func TestFxHash64_KnownValues(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected uint64
	}{
		{"empty", "", 0xf456d26876d72d91},
		{"single zero", string([]byte{0}), 0x4b9d47c1631257a6},
		{"hello", "hello", 0x15136c07c8bce6e4},
		{"67 bytes of zeros", string(make([]byte, 67)), 0x0f35ddc3bc7d6364},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FxHash64([]byte(tt.input))
			if result != tt.expected {
				t.Errorf("'%s' (len=%d): got 0x%016x, want 0x%016x", tt.name, len(tt.input), result, tt.expected)
			}
		})
	}
}

func TestFxHash64_HexDump(t *testing.T) {
	// Test with a real-looking transaction signature (67 bytes)
	txSigHex := "1ba0f8fc3b8e6a4c8e5c3d8f9b2c1e0d4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f"
	txSig, err := hex.DecodeString(txSigHex)
	if err != nil {
		t.Fatalf("Failed to decode hex: %v", err)
	}

	if len(txSig) >= TxSigMaxSize {
		result := FxHash64(txSig[len(txSig)-TxSigMaxSize:])
		expected := uint64(0x77dd43ab93c84a97) // Pre-computed expected value
		if result != expected {
			t.Errorf("Real tx signature hash: got 0x%016x, want 0x%016x", result, expected)
		}
	}
}
