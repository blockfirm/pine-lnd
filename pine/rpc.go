package pine

import (
	context "context"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/lnwallet"
	"google.golang.org/grpc"
)

// SignMessage signs a message using the Pine Lightning API.
func SignMessage(pubKey *btcec.PublicKey, msg []byte) (*btcec.Signature, error) {
	fmt.Print("\n[PINE]: pine→SignMessage")

	conn, err := grpc.Dial("0.0.0.0:8910", grpc.WithInsecure())
	if err != nil {
		return nil, err
	}

	client := NewPineClient(conn)

	request := &SignMessageRequest{
		PublicKey: pubKey.SerializeUncompressed(),
		Message:   msg,
	}

	result, err := client.SignMessage(context.Background(), request)
	if err != nil {
		return nil, err
	}

	return btcec.ParseDERSignature(result.Signature, btcec.S256())
}

// ListUnspentWitness returns a list of unspent transaction outputs using
// the Pine Lightning API.
func ListUnspentWitness(minConfs, maxConfs int32) ([]*lnwallet.Utxo, error) {
	fmt.Print("\n[PINE]: pine→ListUnspentWitness")

	conn, err := grpc.Dial("0.0.0.0:8910", grpc.WithInsecure())
	if err != nil {
		return nil, err
	}

	client := NewPineClient(conn)

	request := &ListUnspentWitnessRequest{
		MinConfirmations: minConfs,
		MaxConfirmations: maxConfs,
	}

	result, err := client.ListUnspentWitness(context.Background(), request)
	if err != nil {
		return nil, err
	}

	var utxos []*lnwallet.Utxo

	for _, utxo := range result.Utxos {
		outPointHash, err := chainhash.NewHash(utxo.OutPoint.Hash)

		if err != nil {
			return nil, err
		}

		utxos = append(utxos, &lnwallet.Utxo{
			AddressType:   lnwallet.AddressType(utxo.AddressType),
			Value:         btcutil.Amount(utxo.Value),
			Confirmations: utxo.Confirmations,
			PkScript:      utxo.PkScript,
			OutPoint: wire.OutPoint{
				Hash:  *outPointHash,
				Index: utxo.OutPoint.Index,
			},
		})
	}

	return utxos, nil
}
