package common

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestExecutionRequestToRequest(t *testing.T) {
	b0, err := hex.DecodeString("0096a96086cff07df17668f35f7418ef8798079167e3f4f9b72ecde17b28226137cf454ab1dd20ef5d924786ab3483c2f9003f5102dabe0a27b1746098d1dc17a5d3fbd478759fea9287e4e419b3c3cef20100000000000000b1acdb2c4d3df3f1b8d3bfd33421660df358d84d78d16c4603551935f4b67643373e7eb63dcb16ec359be0ec41fee33b03a16e80745f2374ff1d3c352508ac5d857c6476d3c3bcf7e6ca37427c9209f17be3af5264c0e2132b3dd1156c28b4e9f000000000000000a5c85a60ba2905c215f6a12872e62b1ee037051364244043a5f639aa81b04a204c55e7cc851f29c7c183be253ea1510b001db70c485b6264692f26b8aeaab5b0c384180df8e2184a21a808a3ec8e86ca01000000000000009561731785b48cf1886412234531e4940064584463e96ac63a1a154320227e333fb51addc4a89b7e0d3f862d7c1fd4ea03bd8eb3d8806f1e7daf591cbbbb92b0beb74d13c01617f22c5026b4f9f9f294a8a7c32db895de3b01bee0132c9209e1f100000000000000")
	if err != nil {
		t.Fatalf("Failed to decode hex string: %v", err)
	}

	b1, err := hex.DecodeString("01a94f5374fce5edbc8e2a8697c15331677e6ebf0b85103a5617937691dfeeb89b86a80d5dc9e3c9d3a1a0e7ce311e26e0bb732eabaa47ffa288f0d54de28209a62a7d29d0000000000000000000000000000000000000000000000000000010f698daeed734da114470da559bd4b4c7259e1f7952555241dcbc90cf194a2ef676fc6005f3672fada2a3645edb297a75530100000000000000")
	if err != nil {
		t.Fatalf("Failed to decode hex string: %v", err)
	}

	b2, err := hex.DecodeString("02a94f5374fce5edbc8e2a8697c15331677e6ebf0b85103a5617937691dfeeb89b86a80d5dc9e3c9d3a1a0e7ce311e26e0bb732eabaa47ffa288f0d54de28209a62a7d29d098daeed734da114470da559bd4b4c7259e1f7952555241dcbc90cf194a2ef676fc6005f3672fada2a3645edb297a7553")
	if err != nil {
		t.Fatalf("Failed to decode hex string: %v", err)
	}

	requests := [][]byte{b0, b1, b2}

	executionRequests, err := RequestsToExecutionRequest(requests)
	if err != nil {
		t.Fatalf("Failed to convert requests to execution requests: %v", err)
	}
	if len(executionRequests.Deposits) != 2 {
		t.Fatalf("Expected 2 deposits, got %d", len(executionRequests.Deposits))
	}
	if len(executionRequests.Withdrawals) != 2 {
		t.Fatalf("Expected 2 withdrawals, got %d", len(executionRequests.Withdrawals))
	}
	if len(executionRequests.Consolidations) != 1 {
		t.Fatalf("Expected 1 consolidation, got %d", len(executionRequests.Consolidations))
	}

	roundTrip, err := ExecutionRequestToRequests(executionRequests)
	if err != nil {
		t.Fatalf("Failed to convert execution requests to requests: %v", err)
	}
	if len(roundTrip) != len(requests) {
		t.Fatalf("Expected %d requests, got %d", len(requests), len(roundTrip))
	}
	for i, request := range requests {
		if !bytes.Equal(request, roundTrip[i]) {
			t.Fatalf("Expected request %d to be equal, got %x, expected %x", i, roundTrip[i], request)
		}
	}
}
