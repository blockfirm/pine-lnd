package serializers

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/pine/rpc"
)

// DeserializeUtxo deserializes an rpc.Utxo into an lnwallet.Utxo.
func DeserializeUtxo(utxo *rpc.Utxo) (*lnwallet.Utxo, error) {
	transactionHash, err := chainhash.NewHash(utxo.TransactionHash)
	if err != nil {
		fmt.Println("Error when converting hash")
		return nil, err
	}

	return &lnwallet.Utxo{
		AddressType:   lnwallet.AddressType(utxo.AddressType),
		Value:         btcutil.Amount(utxo.Value),
		Confirmations: utxo.Confirmations,
		PkScript:      utxo.PkScript,
		OutPoint: wire.OutPoint{
			Hash:  *transactionHash,
			Index: utxo.Vout,
		},
	}, nil
}
