package common

import (
	"testing"
)

func TestGetKeyForCachingPayload(t *testing.T) {
	tests := []struct {
		name           string
		slot           uint64
		keyType        string
		parentHash     string
		blockHash      string
		proposerPubkey string
		expected       string
	}{
		{
			name:           "Proxy keyType with no spaces",
			slot:           12345,
			keyType:        "proxy",
			parentHash:     "abcdef",
			blockHash:      "123456",
			proposerPubkey: "pubkey",
			expected:       "12345_abcdef_123456_pubkey",
		},
		{
			name:           "Regional keyType with no spaces",
			slot:           67890,
			keyType:        "regional",
			parentHash:     "abcdef",
			blockHash:      "123456",
			proposerPubkey: "pubkey",
			expected:       "67890_abcdef_123456_pubkey",
		},
		{
			name:           "Proxy keyType with spaces",
			slot:           11111,
			keyType:        "proxy",
			parentHash:     "  abc def  ",
			blockHash:      "  123 456  ",
			proposerPubkey: "  pub key  ",
			expected:       "11111_abcdef_123456_pubkey",
		},
		{
			name:           "Regional keyType with spaces",
			slot:           44444,
			keyType:        "regional",
			parentHash:     "  abc def  ",
			blockHash:      "  123 456  ",
			proposerPubkey: "  pub key  ",
			expected:       "44444_abcdef_123456_pubkey",
		},
		{
			name:           "Empty parentHash, blockHash, and proposerPubkey with proxy",
			slot:           55555,
			keyType:        "proxy",
			parentHash:     "",
			blockHash:      "",
			proposerPubkey: "",
			expected:       "55555___",
		},
		{
			name:           "Empty parentHash, blockHash, and proposerPubkey with regional",
			slot:           66666,
			keyType:        "regional",
			parentHash:     "",
			blockHash:      "",
			proposerPubkey: "",
			expected:       "66666___",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetKeyForCachingPayload(tt.slot, tt.parentHash, tt.blockHash, tt.proposerPubkey)
			if result != tt.expected {
				t.Errorf("Got %q, expected %q", result, tt.expected)
			}
		})
	}
}
