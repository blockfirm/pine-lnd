package pine

import (
	context "context"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/input"
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

	response, err := client.SignMessage(context.Background(), request)
	if err != nil {
		return nil, err
	}

	return btcec.ParseDERSignature(response.Signature, btcec.S256())
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

	response, err := client.ListUnspentWitness(context.Background(), request)
	if err != nil {
		fmt.Printf("\nError when calling ListUnspentWitness RPC\n")
		return nil, err
	}

	var utxos []*lnwallet.Utxo

	for _, utxo := range response.Utxos {
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

// LockOutpoint marks an unspent transaction output as reserved.
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

// UnlockOutpoint unmarks an unspent transaction output as reserved.
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

// NewAddress returns a new address.
func NewAddress(t lnwallet.AddressType, change bool, netParams *chaincfg.Params) (btcutil.Address, error) {
	fmt.Print("\n[PINE]: pine→NewAddress\n")

	client, err := getClient()
	if err != nil {
		return nil, err
	}

	request := &NewAddressRequest{
		Type:   uint32(t),
		Change: change,
	}

	response, err := client.NewAddress(context.Background(), request)
	if err != nil {
		fmt.Printf("\nError when calling NewAddress RPC\n")
		return nil, err
	}

	address, err := btcutil.DecodeAddress(response.Address, netParams)
	if err != nil {
		fmt.Printf("\nError when decoding address\n")
		return nil, err
	}

	return address, nil
}

// FetchInputInfo returns information about an unspent transaction input
// belonging to this wallet.
func FetchInputInfo(prevOut *wire.OutPoint) (*wire.TxOut, error) {
	fmt.Print("\n[PINE]: pine→FetchInputInfo\n")

	client, err := getClient()
	if err != nil {
		return nil, err
	}

	request := &FetchInputInfoRequest{
		Hash:  prevOut.Hash.CloneBytes(),
		Index: prevOut.Index,
	}

	response, err := client.FetchInputInfo(context.Background(), request)
	if err != nil {
		fmt.Printf("\nError when calling FetchInputInfo RPC\n")
		return nil, err
	}

	txOut := wire.NewTxOut(response.Value, response.PkScript)
	return txOut, nil
}

// SignOutputRaw signs a transaction based on the passed sign descriptor.
func SignOutputRaw(tx *wire.MsgTx, signDesc *input.SignDescriptor) ([]byte, error) {
	fmt.Print("\n[PINE]: pine→SignOutputRaw\n")

	client, err := getClient()
	if err != nil {
		return nil, err
	}

	inputs := make([]*TransactionInput, len(tx.TxIn))
	for index, input := range tx.TxIn {
		inputs[index] = &TransactionInput{
			TransactionHash: input.PreviousOutPoint.Hash.CloneBytes(),
			Index:           input.PreviousOutPoint.Index,
			SignatureScript: input.SignatureScript,
			Witness:         input.Witness,
			Sequence:        input.Sequence,
		}
	}

	outputs := make([]*TransactionOutput, len(tx.TxOut))
	for index, output := range tx.TxOut {
		outputs[index] = &TransactionOutput{
			Value:    output.Value,
			PkScript: output.PkScript,
		}
	}

	transaction := &Transaction{
		Version:  tx.Version,
		Inputs:   inputs,
		Outputs:  outputs,
		LockTime: tx.LockTime,
	}

	signDescriptor := &SignDescriptor{
		KeyDescriptor: &KeyDescriptor{
			KeyLocator: &KeyLocator{
				KeyFamily: uint32(signDesc.KeyDesc.KeyLocator.Family),
				Index:     signDesc.KeyDesc.KeyLocator.Index,
			},
		},
		SingleTweak:   signDesc.SingleTweak,
		WitnessScript: signDesc.WitnessScript,
		Output: &TransactionOutput{
			Value:    signDesc.Output.Value,
			PkScript: signDesc.Output.PkScript,
		},
		HashType: uint32(signDesc.HashType),
		SigHashes: &TransactionSigHashes{
			HashPrevOuts: signDesc.SigHashes.HashPrevOuts.CloneBytes(),
			HashSequence: signDesc.SigHashes.HashSequence.CloneBytes(),
			HashOutputs:  signDesc.SigHashes.HashOutputs.CloneBytes(),
		},
		InputIndex: uint32(signDesc.InputIndex),
	}

	if signDesc.KeyDesc.PubKey != nil {
		signDescriptor.KeyDescriptor.PublicKey = signDesc.KeyDesc.PubKey.SerializeCompressed()
	}

	if signDesc.DoubleTweak != nil {
		signDescriptor.DoubleTweak = signDesc.DoubleTweak.Serialize()
	}

	request := &SignOutputRawRequest{
		Transaction:    transaction,
		SignDescriptor: signDescriptor,
	}

	response, err := client.SignOutputRaw(context.Background(), request)
	if err != nil {
		fmt.Printf("\nError when calling SignOutputRaw RPC\n")
		return nil, err
	}

	return response.Signature, nil
}
