package common

import relaygrpc "github.com/bloXroute-Labs/relay-grpc"

type VersionedPayloadInfo struct {
	Response      []byte
	Slot          uint64
	ParentHash    string
	BlockHash     string
	Pubkey        string
	BlockValue    string
	ServerMessage string
}

func BuildVersionedPayloadInfo(res []byte, slot uint64, parentHash, blockHash, pubKey, blockValue string) *VersionedPayloadInfo {
	return &VersionedPayloadInfo{
		Response:   res,
		Slot:       slot,
		ParentHash: parentHash,
		BlockHash:  blockHash,
		Pubkey:     pubKey,
		BlockValue: blockValue,
	}
}
func BuildVersionedPayloadInfoFromGrpcResponse(in *relaygrpc.GetPayloadResponse) *VersionedPayloadInfo {
	return &VersionedPayloadInfo{
		Response:      in.GetVersionedExecutionPayload(),
		Slot:          in.GetSlot(),
		ParentHash:    in.GetParentHash(),
		BlockHash:     in.GetBlockHash(),
		Pubkey:        in.GetPubkey(),
		BlockValue:    in.GetBlockValue(),
		ServerMessage: in.GetMessage(),
	}
}

func (v *VersionedPayloadInfo) SetResponse(in []byte) {
	if v != nil {
		v.Response = in
	}
}

func (v *VersionedPayloadInfo) SetSlot(slot uint64) {
	if v != nil {
		v.Slot = slot
	}
}

func (v *VersionedPayloadInfo) SetParentHash(ph string) {
	if v != nil {
		v.ParentHash = ph
	}
}

func (v *VersionedPayloadInfo) SetBlockHash(bh string) {
	if v != nil {
		v.BlockHash = bh
	}
}

func (v *VersionedPayloadInfo) SetPubkey(pk string) {
	if v != nil {
		v.Pubkey = pk
	}
}

func (v *VersionedPayloadInfo) SetBlockValue(bv string) {
	if v != nil {
		v.BlockValue = bv
	}
}
func (v *VersionedPayloadInfo) GetResponse() []byte {
	if v != nil {
		return v.Response
	}
	return nil
}
func (v *VersionedPayloadInfo) GetSlot() uint64 {
	if v != nil {
		return v.Slot
	}
	return 0
}

func (v *VersionedPayloadInfo) GetParentHash() string {
	if v != nil {
		return v.ParentHash
	}
	return ""
}

func (v *VersionedPayloadInfo) GetBlockHash() string {
	if v != nil {
		return v.BlockHash
	}
	return ""
}

func (v *VersionedPayloadInfo) GetPubkey() string {
	if v != nil {
		return v.Pubkey
	}
	return ""
}

func (v *VersionedPayloadInfo) GetBlockValue() string {
	if v != nil {
		return v.BlockValue
	}
	return ""
}

func (v *VersionedPayloadInfo) Copy() *VersionedPayloadInfo {
	if v == nil {
		return nil
	}
	newResponse := make([]byte, len(v.Response))
	copy(newResponse, v.Response)
	return &VersionedPayloadInfo{
		Response:      newResponse,
		Slot:          v.Slot,
		ParentHash:    v.ParentHash,
		BlockHash:     v.BlockHash,
		Pubkey:        v.Pubkey,
		BlockValue:    v.BlockValue,
		ServerMessage: v.ServerMessage,
	}
}
