package serializers

import (
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/pine/rpc"
)

// SerializeMsgTx serializes a wire.MsgTx into a rpc.Transaction.
func SerializeMsgTx(tx *wire.MsgTx) *rpc.Transaction {
	inputs := make([]*rpc.TransactionInput, len(tx.TxIn))
	for index, input := range tx.TxIn {
		inputs[index] = &rpc.TransactionInput{
			TransactionHash: input.PreviousOutPoint.Hash.CloneBytes(),
			Index:           input.PreviousOutPoint.Index,
			SignatureScript: input.SignatureScript,
			Witness:         input.Witness,
			Sequence:        input.Sequence,
		}
	}

	outputs := make([]*rpc.TransactionOutput, len(tx.TxOut))
	for index, output := range tx.TxOut {
		outputs[index] = &rpc.TransactionOutput{
			Value:    output.Value,
			PkScript: output.PkScript,
		}
	}

	transaction := &rpc.Transaction{
		Version:  tx.Version,
		Inputs:   inputs,
		Outputs:  outputs,
		LockTime: tx.LockTime,
	}

	return transaction
}

// SerializeSignDescriptor serializes an input.SignDescriptor into a rpc.SignDescriptor.
func SerializeSignDescriptor(signDesc *input.SignDescriptor) *rpc.SignDescriptor {
	signDescriptor := &rpc.SignDescriptor{
		KeyDescriptor: &rpc.KeyDescriptor{
			KeyLocator: &rpc.KeyLocator{
				KeyFamily: uint32(signDesc.KeyDesc.KeyLocator.Family),
				Index:     signDesc.KeyDesc.KeyLocator.Index,
			},
		},
		SingleTweak:   signDesc.SingleTweak,
		WitnessScript: signDesc.WitnessScript,
		Output: &rpc.TransactionOutput{
			Value:    signDesc.Output.Value,
			PkScript: signDesc.Output.PkScript,
		},
		HashType: uint32(signDesc.HashType),
		SigHashes: &rpc.TransactionSigHashes{
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
