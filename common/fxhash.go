package common

import (
	"encoding/binary"
	"math/bits"
)

// FxHasher implements the Rust rustc-hash FxHasher algorithm (version 2.0+) for 64-bit arch.
// This is a polynomial hash with wyhash-inspired byte compression and rotation finalization
// Compatible with: https://github.com/rust-lang/rustc-hash/blob/master/src/lib.rs
type FxHasher struct {
	hash uint64
}

const (
	// K is the multiplicative constant for the polynomial hash
	// From "Computationally Easy, Spectrally Good Multipliers for Congruential
	// Pseudorandom Number Generators" by Guy Steele and Sebastiano Vigna
	K uint64 = 0xf1357aea2e62a9c5

	// Seeds for byte hashing (digits of pi)
	seed1 uint64 = 0x243f6a8885a308d3
	seed2 uint64 = 0x13198a2e03707344

	// Constant to prevent trivial zero collapse in hash_bytes
	preventTrivialZeroCollapse uint64 = 0xa4093822299f31d0

	// Rotation amount for finish() - moves high-entropy top bits to bottom
	rotateAmount = 26
)

// NewFxHasher creates a new FxHasher with seed 0 (default)
func NewFxHasher() *FxHasher {
	return &FxHasher{hash: 0}
}

// NewFxHasherWithSeed creates a new FxHasher with a custom seed
func NewFxHasherWithSeed(seed uint64) *FxHasher {
	return &FxHasher{hash: seed}
}

// Write implements the hash.Hash interface
// Compresses bytes to u64 and adds to polynomial hash
func (f *FxHasher) Write(b []byte) (n int, err error) {
	compressed := hashBytes(b)
	f.addToHash(compressed)
	return len(b), nil
}

// Sum appends the current hash to b and returns the resulting slice
func (f *FxHasher) Sum(b []byte) []byte {
	hash := f.Sum64()
	return binary.LittleEndian.AppendUint64(b, hash)
}

// Reset resets the hasher to its initial state
func (f *FxHasher) Reset() {
	f.hash = 0
}

// Size returns the number of bytes Sum will return
func (f *FxHasher) Size() int {
	return 8
}

// BlockSize returns the hasher's underlying block size
func (f *FxHasher) BlockSize() int {
	return 8
}

// Sum64 returns the current 64-bit hash value with rotation finalization
func (f *FxHasher) Sum64() uint64 {
	// Rotate left by 26 bits to move high-entropy top bits to bottom
	// This is optimal for hash table implementations that use bottom bits
	return bits.RotateLeft64(f.hash, rotateAmount)
}

// addToHash adds a value to the polynomial hash
func (f *FxHasher) addToHash(i uint64) {
	f.hash = (f.hash + i) * K
}

// WriteU64 writes a u64 value directly to the hash
func (f *FxHasher) WriteU64(i uint64) {
	f.addToHash(i)
}

// hashBytes implements the wyhash-inspired byte hashing algorithm
// This is optimized for small strings and small code size
func hashBytes(bytes []byte) uint64 {
	length := len(bytes)
	s0 := seed1
	s1 := seed2

	if length <= 16 {
		// XOR input into s0, s1
		if length >= 8 {
			s0 ^= binary.LittleEndian.Uint64(bytes[0:8])
			s1 ^= binary.LittleEndian.Uint64(bytes[length-8:])
		} else if length >= 4 {
			s0 ^= uint64(binary.LittleEndian.Uint32(bytes[0:4]))
			s1 ^= uint64(binary.LittleEndian.Uint32(bytes[length-4:]))
		} else if length > 0 {
			lo := bytes[0]
			mid := bytes[length/2]
			hi := bytes[length-1]
			s0 ^= uint64(lo)
			s1 ^= (uint64(hi) << 8) | uint64(mid)
		}
	} else {
		// Handle bulk (can partially overlap with suffix)
		off := 0
		for off < length-16 {
			x := binary.LittleEndian.Uint64(bytes[off : off+8])
			y := binary.LittleEndian.Uint64(bytes[off+8 : off+16])

			// Replace s1 with a mix of s0, x, and y, and s0 with s1
			// This ensures the compiler can unroll this loop into two
			// independent streams, one operating on s0, the other on s1
			//
			// Since zeroes are a common input we prevent an immediate trivial
			// collapse of the hash function by XOR'ing a constant with y
			t := multiplyMix(s0^x, preventTrivialZeroCollapse^y)
			s0 = s1
			s1 = t
			off += 16
		}

		// Process suffix (last 16 bytes, may overlap with bulk)
		suffix := bytes[length-16:]
		s0 ^= binary.LittleEndian.Uint64(suffix[0:8])
		s1 ^= binary.LittleEndian.Uint64(suffix[8:16])
	}

	return multiplyMix(s0, s1) ^ uint64(length)
}

// multiplyMix performs 64x64->128 bit widening multiplication and mixes high/low halves
// This is a single mul instruction on x86-64, one mul plus one mulhi on ARM64
func multiplyMix(x, y uint64) uint64 {
	// Full u64 x u64 -> u128 product
	hi, lo := bits.Mul64(x, y)

	// XOR high and low halves to get good mixing
	// The middle bits of the full product fluctuate the most with small
	// changes in the input (top bits of lo and bottom bits of hi)
	return lo ^ hi
}

// FxHash64 is a convenience function that hashes a byte slice and returns the 64-bit hash
// This is equivalent to creating a new hasher, writing the bytes, and calling Sum64()
func FxHash64(b []byte) uint64 {
	h := NewFxHasher()
	h.Write(b)
	return h.Sum64()
}

// FxHash64WithSeed is like FxHash64 but uses a custom seed
func FxHash64WithSeed(b []byte, seed uint64) uint64 {
	h := NewFxHasherWithSeed(seed)
	h.Write(b)
	return h.Sum64()
}
