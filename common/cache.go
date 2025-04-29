package common

import (
	"strconv"
	"strings"
)

func GetKeyForCachingPayload(slot uint64, parentHash, blockHash, proposerPubkey string) string {
	clean := func(s string) string {
		if strings.Contains(s, " ") {
			return strings.ReplaceAll(strings.TrimSpace(s), " ", "")
		}
		return s
	}
	// Use strings.Builder for efficient string concatenation
	var sb strings.Builder
	sb.Grow(64)                                  // Preallocate memory to reduce allocations
	sb.WriteString(strconv.FormatUint(slot, 10)) // Convert uint64 to string efficiently
	sb.WriteByte('_')
	sb.WriteString(clean(parentHash))
	sb.WriteByte('_')
	sb.WriteString(clean(blockHash))
	sb.WriteByte('_')
	sb.WriteString(clean(proposerPubkey))

	return sb.String()
}
