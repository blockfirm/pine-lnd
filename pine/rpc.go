package pine

import (
	context "context"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/input"
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
		fmt.Println("Error when connecting Pine RPC:")
		fmt.Println(err)
		return nil, err
	}

	return NewPineClient(conn), nil
}

func init() {
	client, err := getClient()
	if err != nil {
		fmt.Println("Unable to connect to Pine RPC")
		return
	}

	rpcClient = client
	fmt.Println("Connected to Pine RPC")
}

// SignMessage signs a message using the Pine Lightning API.
func SignMessage(pubKey *btcec.PublicKey, msg []byte) (*btcec.Signature, error) {
	fmt.Println("[PINE]: pine→SignMessage")

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
func ListUnspentWitness(minConfs, maxConfs int32) ([]*Utxo, error) {
	fmt.Println("[PINE]: pine→ListUnspentWitness")

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
		fmt.Println("Error when calling ListUnspentWitness RPC:")
		fmt.Println(err)
		return nil, err
	}

	return response.Utxos, nil
}

// LockOutpoint marks an unspent transaction output as reserved.
func LockOutpoint(o wire.OutPoint) error {
	fmt.Println("[PINE]: pine→LockOutpoint")

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
		fmt.Println("Error when calling LockOutpoint RPC:")
		fmt.Println(err)
		return err
	}

	return nil
}

// UnlockOutpoint unmarks an unspent transaction output as reserved.
func UnlockOutpoint(o wire.OutPoint) error {
	fmt.Println("[PINE]: pine→UnlockOutpoint")

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
		fmt.Println("Error when calling UnlockOutpoint RPC")
		fmt.Println(err)
		return err
	}

	return nil
}

// NewAddress returns a new address.
func NewAddress(t uint8, change bool, netParams *chaincfg.Params) (btcutil.Address, error) {
	fmt.Println("[PINE]: pine→NewAddress")

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
		fmt.Println("Error when calling NewAddress RPC:")
		fmt.Println(err)
		return nil, err
	}

	address, err := btcutil.DecodeAddress(response.Address, netParams)
	if err != nil {
		fmt.Println("Error when decoding address")
		return nil, err
	}

	return address, nil
}

// FetchInputInfo returns information about an unspent transaction input
// belonging to this wallet.
func FetchInputInfo(prevOut *wire.OutPoint) (*wire.TxOut, error) {
	fmt.Println("[PINE]: pine→FetchInputInfo")

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
		fmt.Println("Error when calling FetchInputInfo RPC:")
		fmt.Println(err)
		return nil, err
	}

	txOut := wire.NewTxOut(response.Value, response.PkScript)
	return txOut, nil
}

// SignOutputRaw signs a transaction based on the passed sign descriptor.
func SignOutputRaw(tx *wire.MsgTx, signDesc *input.SignDescriptor) ([]byte, error) {
	fmt.Println("[PINE]: pine→SignOutputRaw")

	client, err := getClient()
	if err != nil {
		return nil, err
	}

	transaction := serializeMsgTx(tx)
	signDescriptor := serializeSignDescriptor(signDesc)

	request := &SignOutputRawRequest{
		Transaction:    transaction,
		SignDescriptor: signDescriptor,
	}

	response, err := client.SignOutputRaw(context.Background(), request)
	if err != nil {
		fmt.Println("Error when calling SignOutputRaw RPC:")
		fmt.Println(err)
		return nil, err
	}

	return response.Signature, nil
}

// ComputeInputScript returns an input script for the passed transaction and input.
func ComputeInputScript(tx *wire.MsgTx, signDesc *input.SignDescriptor) (*input.Script, error) {
	fmt.Println("[PINE]: pine→ComputeInputScript")

	client, err := getClient()
	if err != nil {
		return nil, err
	}

	transaction := serializeMsgTx(tx)
	signDescriptor := serializeSignDescriptor(signDesc)

	request := &ComputeInputScriptRequest{
		Transaction:    transaction,
		SignDescriptor: signDescriptor,
	}

	response, err := client.ComputeInputScript(context.Background(), request)
	if err != nil {
		fmt.Println("Error when calling ComputeInputScript RPC:")
		fmt.Println(err)
		return nil, err
	}

	inputScript := &input.Script{
		Witness:   response.Witness,
		SigScript: response.SignatureScript,
	}

	return inputScript, nil

}

func serializeMsgTx(tx *wire.MsgTx) *Transaction {
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

	return transaction
}

func serializeSignDescriptor(signDesc *input.SignDescriptor) *SignDescriptor {
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
		signDescriptor.KeyDescriptor.PublicKey = signDesc.KeyDesc.PubKey.SerializeUncompressed()
	}

	if signDesc.DoubleTweak != nil {
		signDescriptor.DoubleTweak = signDesc.DoubleTweak.Serialize()
	}

	return signDescriptor
}

// GetRevocationRootKey returns a new private key to be used as a revocation root.
// TODO: This should be replaced with a new RPC method for getting revocation secrets.
func GetRevocationRootKey() (*btcec.PrivateKey, error) {
	fmt.Println("[PINE]: pine→GetRevocationRootKey")

	client, err := getClient()
	if err != nil {
		return nil, err
	}

	request := &GetRevocationRootKeyRequest{}

	response, err := client.GetRevocationRootKey(context.Background(), request)
	if err != nil {
		fmt.Println("Error when calling GetRevocationRootKey RPC:")
		fmt.Println(err)
		return nil, err
	}

	privateKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), response.PrivateKey)

	return privateKey, nil
}

// DeriveNextKey derives a new key from the specified key family.
// No private keys are returned, only a key descriptor of one.
func DeriveNextKey(keyFam uint32) (*KeyDescriptor, error) {
	fmt.Println("[PINE]: pine→DeriveNextKey")

	client, err := getClient()
	if err != nil {
		return &KeyDescriptor{}, err
	}

	request := &DeriveNextKeyRequest{
		KeyFamily: keyFam,
	}

	response, err := client.DeriveNextKey(context.Background(), request)
	if err != nil {
		fmt.Println("Error when calling DeriveNextKey RPC:")
		fmt.Println(err)
		return &KeyDescriptor{}, err
	}

	return response.KeyDescriptor, nil
}
