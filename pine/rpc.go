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

const rpcTarget = "0.0.0.0:8910"

var rpcClient PineClient

func getClient() (PineClient, error) {
	if rpcClient != nil {
		return rpcClient, nil
	}

	conn, err := grpc.Dial(rpcTarget, grpc.WithInsecure())
	if err != nil {
		fmt.Printf("\nError when connecting Pine RPC\n")
		return nil, err
	}

	rpcClient = NewPineClient(conn)
	return rpcClient, nil
}

// SignMessage signs a message using the Pine Lightning API.
func SignMessage(pubKey *btcec.PublicKey, msg []byte) (*btcec.Signature, error) {
	fmt.Print("\n[PINE]: pine→SignMessage\n")

	client, err := getClient()
	if err != nil {
		return nil, err
	}

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
	fmt.Print("\n[PINE]: pine→ListUnspentWitness\n")

	client, err := getClient()
	if err != nil {
		return nil, err
	}

	request := &ListUnspentWitnessRequest{
		MinConfirmations: minConfs,
		MaxConfirmations: maxConfs,
	}

	result, err := client.ListUnspentWitness(context.Background(), request)
	if err != nil {
		fmt.Printf("\nError when calling ListUnspentWitness RPC\n")
		return nil, err
	}

	var utxos []*lnwallet.Utxo

	for _, utxo := range result.Utxos {
		transactionHash, err := chainhash.NewHash(utxo.TransactionHash)

		if err != nil {
			fmt.Printf("\nError when converting hash\n")
			return nil, err
		}

		utxos = append(utxos, &lnwallet.Utxo{
			AddressType:   lnwallet.AddressType(utxo.AddressType),
			Value:         btcutil.Amount(utxo.Value),
			Confirmations: utxo.Confirmations,
			PkScript:      utxo.PkScript,
			OutPoint: wire.OutPoint{
				Hash:  *transactionHash,
				Index: utxo.Vout,
			},
		})
	}

	return utxos, nil
}

// LockOupoint marks an unspent transaction output as reserved.
func LockOutpoint(o wire.OutPoint) error {
	fmt.Print("\n[PINE]: pine→LockOutpoint\n")

	client, err := getClient()
	if err != nil {
		return err
	}

	request := &LockOutpointRequest{
		Hash:  o.Hash.CloneBytes(),
		Index: o.Index,
	}

	_, err = client.LockOutpoint(context.Background(), request)
	if err != nil {
		fmt.Printf("\nError when calling LockOutpoint RPC\n")
		return err
	}

	return nil
}

// UnlockOupoint unmarks an unspent transaction output as reserved.
func UnlockOutpoint(o wire.OutPoint) error {
	fmt.Print("\n[PINE]: pine→UnlockOutpoint\n")

	client, err := getClient()
	if err != nil {
		return err
	}

	request := &UnlockOutpointRequest{
		Hash:  o.Hash.CloneBytes(),
		Index: o.Index,
	}

	_, err = client.UnlockOutpoint(context.Background(), request)
	if err != nil {
		fmt.Printf("\nError when calling UnlockOutpoint RPC\n")
		return err
	}

	return nil
}
