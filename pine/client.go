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

func getClient() (rpc.PineClient, error) {
	if rpcClient != nil {
		return rpcClient, nil
	}

	conn, err := grpc.Dial(rpcTarget, grpc.WithInsecure())
	if err != nil {
		fmt.Println("Error when connecting Pine RPC:")
		fmt.Println(err)
		return nil, err
	}

	return rpc.NewPineClient(conn), nil
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

	request := &rpc.SignMessageRequest{
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
func ListUnspentWitness(minConfs, maxConfs int32) ([]*rpc.Utxo, error) {
	fmt.Println("[PINE]: pine→ListUnspentWitness")

	client, err := getClient()
	if err != nil {
		return nil, err
	}

	request := &rpc.ListUnspentWitnessRequest{
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

	request := &rpc.LockOutpointRequest{
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

	request := &rpc.UnlockOutpointRequest{
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

	request := &rpc.NewAddressRequest{
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
func FetchInputInfo(prevOut *wire.OutPoint) (*rpc.Utxo, error) {
	fmt.Println("[PINE]: pine→FetchInputInfo")

	client, err := getClient()
	if err != nil {
		return nil, err
	}

	request := &rpc.FetchInputInfoRequest{
		Hash:  prevOut.Hash.CloneBytes(),
		Index: prevOut.Index,
	}

	response, err := client.FetchInputInfo(context.Background(), request)
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

	client, err := getClient()
	if err != nil {
		return nil, err
	}

	request := &rpc.SignOutputRawRequest{
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
func ComputeInputScript(transaction *rpc.Transaction, signDescriptor *rpc.SignDescriptor) (*rpc.ComputeInputScriptResponse, error) {
	fmt.Println("[PINE]: pine→ComputeInputScript")

	client, err := getClient()
	if err != nil {
		return nil, err
	}

	request := &rpc.ComputeInputScriptRequest{
		Transaction:    transaction,
		SignDescriptor: signDescriptor,
	}

	response, err := client.ComputeInputScript(context.Background(), request)
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

	client, err := getClient()
	if err != nil {
		return nil, err
	}

	request := &rpc.GetRevocationRootKeyRequest{}

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
func DeriveNextKey(keyFam uint32) (*rpc.KeyDescriptor, error) {
	fmt.Println("[PINE]: pine→DeriveNextKey")

	client, err := getClient()
	if err != nil {
		return &rpc.KeyDescriptor{}, err
	}

	request := &rpc.DeriveNextKeyRequest{
		KeyFamily: keyFam,
	}

	response, err := client.DeriveNextKey(context.Background(), request)
	if err != nil {
		fmt.Println("Error when calling DeriveNextKey RPC:")
		fmt.Println(err)
		return &rpc.KeyDescriptor{}, err
	}

	return response.KeyDescriptor, nil
}
