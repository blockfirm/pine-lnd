package sweep

import (
	"fmt"
	"sort"
	"strings"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

var (
	// DefaultMaxInputsPerTx specifies the default maximum number of inputs
	// allowed in a single sweep tx. If more need to be swept, multiple txes
	// are created and published.
	DefaultMaxInputsPerTx = 100
)

// txInput is an interface that provides the input data required for tx
// generation.
type txInput interface {
	input.Input
	parameters() Params
}

// inputSet is a set of inputs that can be used as the basis to generate a tx
// on.
type inputSet []input.Input

// generateInputPartitionings goes through all given inputs and constructs sets
// of inputs that can be used to generate a sensible transaction. Each set
// contains up to the configured maximum number of inputs. Negative yield
// inputs are skipped. No input sets with a total value after fees below the
// dust limit are returned.
func generateInputPartitionings(sweepableInputs []txInput,
	relayFeePerKW, feePerKW chainfee.SatPerKWeight,
	maxInputsPerTx int, wallet Wallet) ([]inputSet, error) {

	// Sort input by yield. We will start constructing input sets starting
	// with the highest yield inputs. This is to prevent the construction
	// of a set with an output below the dust limit, causing the sweep
	// process to stop, while there are still higher value inputs
	// available. It also allows us to stop evaluating more inputs when the
	// first input in this ordering is encountered with a negative yield.
	//
	// Yield is calculated as the difference between value and added fee
	// for this input. The fee calculation excludes fee components that are
	// common to all inputs, as those wouldn't influence the order. The
	// single component that is differentiating is witness size.
	//
	// For witness size, the upper limit is taken. The actual size depends
	// on the signature length, which is not known yet at this point.
	yields := make(map[wire.OutPoint]int64)
	for _, input := range sweepableInputs {
		size, _, err := input.WitnessType().SizeUpperBound()
		if err != nil {
			return nil, fmt.Errorf(
				"failed adding input weight: %v", err)
		}

		yields[*input.OutPoint()] = input.SignDesc().Output.Value -
			int64(feePerKW.FeeForWeight(int64(size)))
	}

	sort.Slice(sweepableInputs, func(i, j int) bool {
		// Because of the specific ordering and termination condition
		// that is described above, we place force sweeps at the start
		// of the list. Otherwise we can't be sure that they will be
		// included in an input set.
		if sweepableInputs[i].parameters().Force {
			return true
		}

		return yields[*sweepableInputs[i].OutPoint()] >
			yields[*sweepableInputs[j].OutPoint()]
	})

	// Select blocks of inputs up to the configured maximum number.
	var sets []inputSet
	for len(sweepableInputs) > 0 {
		// Start building a set of positive-yield tx inputs under the
		// condition that the tx will be published with the specified
		// fee rate.
		txInputs := newTxInputSet(
			wallet, feePerKW, relayFeePerKW, maxInputsPerTx,
		)

		// From the set of sweepable inputs, keep adding inputs to the
		// input set until the tx output value no longer goes up or the
		// maximum number of inputs is reached.
		txInputs.addPositiveYieldInputs(sweepableInputs)

		// If there are no positive yield inputs, we can stop here.
		inputCount := len(txInputs.inputs)
		if inputCount == 0 {
			return sets, nil
		}

		// Check the current output value and add wallet utxos if
		// needed to push the output value to the lower limit.
		if err := txInputs.tryAddWalletInputsIfNeeded(); err != nil {
			return nil, err
		}

		// If the output value of this block of inputs does not reach
		// the dust limit, stop sweeping. Because of the sorting,
		// continuing with the remaining inputs will only lead to sets
		// with an even lower output value.
		if !txInputs.dustLimitReached() {
			log.Debugf("Set value %v below dust limit of %v",
				txInputs.outputValue, txInputs.dustLimit)
			return sets, nil
		}

		log.Infof("Candidate sweep set of size=%v (+%v wallet inputs), "+
			"has yield=%v, weight=%v",
			inputCount, len(txInputs.inputs)-inputCount,
			txInputs.outputValue-txInputs.walletInputTotal,
			txInputs.weightEstimate.Weight())

		sets = append(sets, txInputs.inputs)
		sweepableInputs = sweepableInputs[inputCount:]
	}

	return sets, nil
}

// createSweepTx builds a signed tx spending the inputs to a the output script.
func createSweepTx(inputs []input.Input, outputPkScript []byte,
	currentBlockHeight uint32, feePerKw chainfee.SatPerKWeight,
	signer input.Signer) (*wire.MsgTx, error) {

	inputs, txWeight := getWeightEstimate(inputs)

	txFee := feePerKw.FeeForWeight(txWeight)

	// Sum up the total value contained in the inputs.
	var totalSum btcutil.Amount
	for _, o := range inputs {
		totalSum += btcutil.Amount(o.SignDesc().Output.Value)
	}

	// Sweep as much possible, after subtracting txn fees.
	sweepAmt := int64(totalSum - txFee)

	// Create the sweep transaction that we will be building. We use
	// version 2 as it is required for CSV. The txn will sweep the amount
	// after fees to the pkscript generated above.
	sweepTx := wire.NewMsgTx(2)
	sweepTx.AddTxOut(&wire.TxOut{
		PkScript: outputPkScript,
		Value:    sweepAmt,
	})

	sweepTx.LockTime = currentBlockHeight

	// Add all inputs to the sweep transaction. Ensure that for each
	// csvInput, we set the sequence number properly.
	for _, input := range inputs {
		sweepTx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: *input.OutPoint(),
			Sequence:         input.BlocksToMaturity(),
		})
	}

	// Before signing the transaction, check to ensure that it meets some
	// basic validity requirements.
	//
	// TODO(conner): add more control to sanity checks, allowing us to
	// delay spending "problem" outputs, e.g. possibly batching with other
	// classes if fees are too low.
	btx := btcutil.NewTx(sweepTx)
	if err := blockchain.CheckTransactionSanity(btx); err != nil {
		return nil, err
	}

	hashCache := txscript.NewTxSigHashes(sweepTx)

	// With all the inputs in place, use each output's unique input script
	// function to generate the final witness required for spending.
	addInputScript := func(idx int, tso input.Input) error {
		inputScript, err := tso.CraftInputScript(
			signer, sweepTx, hashCache, idx,
		)
		if err != nil {
			return err
		}

		sweepTx.TxIn[idx].Witness = inputScript.Witness

		if len(inputScript.SigScript) != 0 {
			sweepTx.TxIn[idx].SignatureScript = inputScript.SigScript
		}

		return nil
	}

	// Finally we'll attach a valid input script to each csv and cltv input
	// within the sweeping transaction.
	for i, input := range inputs {
		if err := addInputScript(i, input); err != nil {
			return nil, err
		}
	}

	log.Infof("Creating sweep transaction %v for %v inputs (%s) "+
		"using %v sat/kw, tx_fee=%v", sweepTx.TxHash(), len(inputs),
		inputTypeSummary(inputs), int64(feePerKw), txFee)

	return sweepTx, nil
}

// getWeightEstimate returns a weight estimate for the given inputs.
// Additionally, it returns counts for the number of csv and cltv inputs.
func getWeightEstimate(inputs []input.Input) ([]input.Input, int64) {
	// We initialize a weight estimator so we can accurately asses the
	// amount of fees we need to pay for this sweep transaction.
	//
	// TODO(roasbeef): can be more intelligent about buffering outputs to
	// be more efficient on-chain.
	var weightEstimate input.TxWeightEstimator

	// Our sweep transaction will pay to a single segwit p2wkh address,
	// ensure it contributes to our weight estimate.
	weightEstimate.AddP2WKHOutput()

	// For each output, use its witness type to determine the estimate
	// weight of its witness, and add it to the proper set of spendable
	// outputs.
	var sweepInputs []input.Input
	for i := range inputs {
		inp := inputs[i]

		wt := inp.WitnessType()
		err := wt.AddWeightEstimation(&weightEstimate)
		if err != nil {
			log.Warn(err)

			// Skip inputs for which no weight estimate can be
			// given.
			continue
		}

		sweepInputs = append(sweepInputs, inp)
	}

	return sweepInputs, int64(weightEstimate.Weight())
}

// inputSummary returns a string containing a human readable summary about the
// witness types of a list of inputs.
func inputTypeSummary(inputs []input.Input) string {
	// Sort inputs by witness type.
	sortedInputs := make([]input.Input, len(inputs))
	copy(sortedInputs, inputs)
	sort.Slice(sortedInputs, func(i, j int) bool {
		return sortedInputs[i].WitnessType().String() <
			sortedInputs[j].WitnessType().String()
	})

	var parts []string
	for _, i := range sortedInputs {
		part := fmt.Sprintf("%v (%v)",
			*i.OutPoint(), i.WitnessType())

		parts = append(parts, part)
	}
	return strings.Join(parts, ", ")
}
