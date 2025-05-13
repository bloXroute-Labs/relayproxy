package common

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strconv"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
)

type SignerFlag struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	AccountID  string `json:"account_id"`
}

type WalletAccount struct {
	Pubkey           common.Address
	Nonce            *big.Int
	Balance          *big.Int
	privateKey       *ecdsa.PrivateKey
	AccountID        string
	LastUpdatedBlock uint64
}

func (w *WalletAccount) String() string {
	//Exclude private key
	return "Pubkey: " + w.Pubkey.String() + " AccountID: " + w.AccountID + " Nonce: " + w.Nonce.String() + " Balance: " + w.Balance.String() + " LastUpdatedBlock: " + strconv.Itoa(int(w.LastUpdatedBlock))
}

func NewWalletAccounts(SignersArr []SignerFlag) (*map[string]*WalletAccount, []common.Address, error) {
	walletAccounts := make(map[string]*WalletAccount)
	pubkeys := make([]common.Address, 0)
	for _, bidadjustmentSigner := range SignersArr {
		signingKey, err := crypto.HexToECDSA(bidadjustmentSigner.PrivateKey)
		if err != nil {
			return &walletAccounts, pubkeys, err
		}
		pubkey := crypto.PubkeyToAddress(signingKey.PublicKey)
		if pubkey.String() != bidadjustmentSigner.PublicKey {
			return &walletAccounts, pubkeys, fmt.Errorf("Public key does not match expected %s %s", pubkey.String(), bidadjustmentSigner.PublicKey)
		}
		walletAccounts[pubkey.String()] = &WalletAccount{
			Pubkey:           pubkey,
			AccountID:        bidadjustmentSigner.AccountID,
			Nonce:            new(big.Int).SetUint64(0),
			Balance:          new(big.Int).SetUint64(0),
			privateKey:       signingKey,
			LastUpdatedBlock: 0,
		}
		pubkeys = append(pubkeys, pubkey)
	}
	return &walletAccounts, pubkeys, nil
}

func (w *WalletAccount) SignTransfer(ctx context.Context, fromAddress common.Address, toAddress common.Address, value *uint256.Int, gasFeeCap, gasLimit uint64, chainID uint64) (bellatrix.Transaction, *types.Transaction, error) {
	chainIDBigInt := new(big.Int).SetUint64(chainID)
	tx, err := types.SignNewTx(w.privateKey, types.LatestSignerForChainID(chainIDBigInt), &types.DynamicFeeTx{
		ChainID:   chainIDBigInt,
		Nonce:     w.Nonce.Uint64(),
		GasTipCap: new(big.Int),
		GasFeeCap: big.NewInt(int64(gasFeeCap)),
		Gas:       gasLimit,
		To:        &toAddress,
		Value:     value.ToBig(),
	})

	if err != nil {
		return nil, tx, err
	}
	txByte, err := tx.MarshalBinary()
	if err != nil {
		return nil, tx, err
	}

	return txByte, tx, nil

}
