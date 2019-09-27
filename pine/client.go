package pine

import (
	context "context"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/pine/rpc"
	"google.golang.org/grpc"
)

const rpcTarget = "0.0.0.0:8910"

var rpcClient rpc.PineClient

func getClient(pineID string) (rpc.PineClient, error) {
	if rpcClient != nil {
		return rpcClient, nil
	}

	creds := pineCredentials{id: pineID}

	conn, err := grpc.Dial(
		rpcTarget,
		grpc.WithInsecure(),
		grpc.WithPerRPCCredentials(creds),
	)

	if err != nil {
		return nil, err
	}

	return rpc.NewPineClient(conn), nil
}

// Connect connects to the Pine Lightning RPC.
func Connect(pineID string) error {
	if pineID == "" {
		return fmt.Errorf("Pine ID cannot be empty")
	}

	client, err := getClient(pineID)
	if err != nil {
		return fmt.Errorf("Unable to connect to Pine RPC: %v", err)
	}

	rpcClient = client

	return nil
}

// SignMessage signs a message using the Pine Lightning API.
func SignMessage(pubKey *btcec.PublicKey, msg []byte) (*btcec.Signature, error) {
	fmt.Println("[PINE]: pine→SignMessage")

	request := &rpc.SignMessageRequest{
		PublicKey: pubKey.SerializeUncompressed(),
		Message:   msg,
	}

	response, err := rpcClient.SignMessage(context.Background(), request)
	if err != nil {
		return nil, err
	}

	return btcec.ParseDERSignature(response.Signature, btcec.S256())
}

// ListUnspentWitness returns a list of unspent transaction outputs using
// the Pine Lightning API.
func ListUnspentWitness(minConfs, maxConfs int32) ([]*rpc.Utxo, error) {
	fmt.Println("[PINE]: pine→ListUnspentWitness")

	request := &rpc.ListUnspentWitnessRequest{
		MinConfirmations: minConfs,
		MaxConfirmations: maxConfs,
	}

	response, err := rpcClient.ListUnspentWitness(context.Background(), request)
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

	request := &rpc.LockOutpointRequest{
		Hash:  o.Hash.CloneBytes(),
		Index: o.Index,
	}

	_, err := rpcClient.LockOutpoint(context.Background(), request)
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

	request := &rpc.UnlockOutpointRequest{
		Hash:  o.Hash.CloneBytes(),
		Index: o.Index,
	}

	_, err := rpcClient.UnlockOutpoint(context.Background(), request)
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

	request := &rpc.NewAddressRequest{
		Type:   uint32(t),
		Change: change,
	}

	response, err := rpcClient.NewAddress(context.Background(), request)
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

// IsOurAddress returns whether or not the passed address belongs to
// the user's wallet.
func IsOurAddress(a btcutil.Address) bool {
	fmt.Println("[PINE]: pine→IsOurAddress")

	request := &rpc.IsOurAddressRequest{
		Address: a.String(),
	}

	response, err := rpcClient.IsOurAddress(context.Background(), request)
	if err != nil {
		fmt.Println("Error when calling IsOurAddress RPC:")
		fmt.Println(err)
		return false
	}

	return response.IsOurAddress
}

// FetchInputInfo returns information about an unspent transaction input
// belonging to this wallet.
func FetchInputInfo(prevOut *wire.OutPoint) (*rpc.Utxo, error) {
	fmt.Println("[PINE]: pine→FetchInputInfo")

	request := &rpc.FetchInputInfoRequest{
		Hash:  prevOut.Hash.CloneBytes(),
		Index: prevOut.Index,
	}

	response, err := rpcClient.FetchInputInfo(context.Background(), request)
	if err != nil {
		fmt.Println("Error when calling FetchInputInfo RPC:")
		fmt.Println(err)
		return nil, err
	}

	return response.Utxo, nil
}

// SignOutputRaw signs a transaction based on the passed sign descriptor.
func SignOutputRaw(transaction *rpc.Transaction, signDescriptor *rpc.SignDescriptor) ([]byte, error) {
	fmt.Println("[PINE]: pine→SignOutputRaw")

	request := &rpc.SignOutputRawRequest{
		Transaction:    transaction,
		SignDescriptor: signDescriptor,
	}

	response, err := rpcClient.SignOutputRaw(context.Background(), request)
	if err != nil {
		fmt.Println("Error when calling SignOutputRaw RPC:")
		fmt.Println(err)
		return nil, err
	}

	return response.Signature, nil
}

// ComputeInputScript returns an input script for the passed transaction and input.
func ComputeInputScript(transaction *rpc.Transaction, signDescriptor *rpc.SignDescriptor) (*rpc.ComputeInputScriptResponse, error) {
	fmt.Println("[PINE]: pine→ComputeInputScript")

	request := &rpc.ComputeInputScriptRequest{
		Transaction:    transaction,
		SignDescriptor: signDescriptor,
	}

	response, err := rpcClient.ComputeInputScript(context.Background(), request)
	if err != nil {
		fmt.Println("Error when calling ComputeInputScript RPC:")
		fmt.Println(err)
		return nil, err
	}

	return response, nil
}

// GetRevocationRootKey returns a new private key to be used as a revocation root.
// TODO: This should be replaced with a new RPC method for getting revocation secrets.
func GetRevocationRootKey() (*btcec.PrivateKey, error) {
	fmt.Println("[PINE]: pine→GetRevocationRootKey")

	request := &rpc.GetRevocationRootKeyRequest{}

	response, err := rpcClient.GetRevocationRootKey(context.Background(), request)
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
func DeriveNextKey(keyFam uint32) (*rpc.KeyDescriptor, error) {
	fmt.Println("[PINE]: pine→DeriveNextKey")

	request := &rpc.DeriveNextKeyRequest{
		KeyFamily: keyFam,
	}

	response, err := rpcClient.DeriveNextKey(context.Background(), request)
	if err != nil {
		fmt.Println("Error when calling DeriveNextKey RPC:")
		fmt.Println(err)
		return &rpc.KeyDescriptor{}, err
	}

	return response.KeyDescriptor, nil
}

// DeriveKey derives a key based on the specified key locator.
// No private keys are returned, only a key descriptor of one.
func DeriveKey(keyFam uint32, keyIndex uint32) (*rpc.KeyDescriptor, error) {
	fmt.Println("[PINE]: pine→DeriveKey")

	request := &rpc.DeriveKeyRequest{
		KeyLocator: &rpc.KeyLocator{
			KeyFamily: keyFam,
			Index:     keyIndex,
		},
	}

	response, err := rpcClient.DeriveKey(context.Background(), request)
	if err != nil {
		fmt.Println("Error when calling DeriveKey RPC:")
		fmt.Println(err)
		return nil, err
	}

	return response.KeyDescriptor, nil
}
