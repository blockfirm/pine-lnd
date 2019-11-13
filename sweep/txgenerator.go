package sweep

import (
	"fmt"
	"sort"
	"strings"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

var (
	// DefaultMaxInputsPerTx specifies the default maximum number of inputs
	// allowed in a single sweep tx. If more need to be swept, multiple txes
	// are created and published.
	DefaultMaxInputsPerTx = 100
)

// inputSet is a set of inputs that can be used as the basis to generate a tx
// on.
type inputSet []input.Input

// generateInputPartitionings goes through all given inputs and constructs sets
// of inputs that can be used to generate a sensible transaction. Each set
// contains up to the configured maximum number of inputs. Negative yield
// inputs are skipped. No input sets with a total value after fees below the
// dust limit are returned.
func generateInputPartitionings(sweepableInputs []input.Input,
	relayFeePerKW, feePerKW chainfee.SatPerKWeight,
	maxInputsPerTx int) ([]inputSet, error) {

	// Calculate dust limit based on the P2WPKH output script of the sweep
	// txes.
	dustLimit := txrules.GetDustThreshold(
		input.P2WPKHSize,
		btcutil.Amount(relayFeePerKW.FeePerKVByte()),
	)

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
		return yields[*sweepableInputs[i].OutPoint()] >
			yields[*sweepableInputs[j].OutPoint()]
	})

	// Select blocks of inputs up to the configured maximum number.
	var sets []inputSet
	for len(sweepableInputs) > 0 {
		// Get the maximum number of inputs from sweepableInputs that
		// we can use to create a positive yielding set from.
		count, outputValue := getPositiveYieldInputs(
			sweepableInputs, maxInputsPerTx, feePerKW,
		)

		// If there are no positive yield inputs left, we can stop
		// here.
		if count == 0 {
			return sets, nil
		}

		// If the output value of this block of inputs does not reach
		// the dust limit, stop sweeping. Because of the sorting,
		// continuing with the remaining inputs will only lead to sets
		// with a even lower output value.
		if outputValue < dustLimit {
			log.Debugf("Set value %v below dust limit of %v",
				outputValue, dustLimit)
			return sets, nil
		}

		log.Infof("Candidate sweep set of size=%v, has yield=%v",
			count, outputValue)

		sets = append(sets, sweepableInputs[:count])
		sweepableInputs = sweepableInputs[count:]
	}

	return sets, nil
}

// getPositiveYieldInputs returns the maximum of a number n for which holds
// that the inputs [0,n) of sweepableInputs have a positive yield.
// Additionally, the total values of these inputs minus the fee is returned.
//
// TODO(roasbeef): Consider including some negative yield inputs too to clean
// up the utxo set even if it costs us some fees up front.  In the spirit of
// minimizing any negative externalities we cause for the Bitcoin system as a
// whole.
func getPositiveYieldInputs(sweepableInputs []input.Input, maxInputs int,
	feePerKW chainfee.SatPerKWeight) (int, btcutil.Amount) {

	var weightEstimate input.TxWeightEstimator

	// Add the sweep tx output to the weight estimate.
	weightEstimate.AddP2WKHOutput()

	var total, outputValue btcutil.Amount
	for idx, input := range sweepableInputs {
		// Can ignore error, because it has already been checked when
		// calculating the yields.
		size, isNestedP2SH, _ := input.WitnessType().SizeUpperBound()

		// Keep a running weight estimate of the input set.
		if isNestedP2SH {
			weightEstimate.AddNestedP2WSHInput(size)
		} else {
			weightEstimate.AddWitnessInput(size)
		}

		newTotal := total + btcutil.Amount(input.SignDesc().Output.Value)

		weight := weightEstimate.Weight()
		fee := feePerKW.FeeForWeight(int64(weight))

		// Calculate the output value if the current input would be
		// added to the set.
		newOutputValue := newTotal - fee

		// If adding this input makes the total output value of the set
		// decrease, this is a negative yield input. It shouldn't be
		// added to the set. We return the current index as the number
		// of inputs, so the current input is being excluded.
		if newOutputValue <= outputValue {
			return idx, outputValue
		}

		// Update running values.
		total = newTotal
		outputValue = newOutputValue

		// Stop if max inputs is reached.
		if idx == maxInputs-1 {
			return maxInputs, outputValue
		}
	}

	// We could add all inputs to the set, so return them all.
	return len(sweepableInputs), outputValue
}

// createSweepTx builds a signed tx spending the inputs to a the output script.
func createSweepTx(inputs []input.Input, outputPkScript []byte,
	currentBlockHeight uint32, feePerKw chainfee.SatPerKWeight,
	signer input.Signer) (*wire.MsgTx, error) {

	inputs, txWeight := getWeightEstimate(inputs)

	log.Infof("Creating sweep transaction for %v inputs (%s) "+
		"using %v sat/kw", len(inputs), inputTypeSummary(inputs),
		int64(feePerKw))

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
	// Count each input by the string representation of its witness type.
	// We also keep track of the keys so we can later sort by them to get
	// a stable output.
	counts := make(map[string]uint32)
	keys := make([]string, 0, len(inputs))
	for _, i := range inputs {
		key := i.WitnessType().String()
		_, ok := counts[key]
		if !ok {
			counts[key] = 0
			keys = append(keys, key)
		}
		counts[key]++
	}
	sort.Strings(keys)

	// Return a nice string representation of the counts by comma joining a
	// slice.
	var parts []string
	for _, witnessType := range keys {
		part := fmt.Sprintf("%d %s", counts[witnessType], witnessType)
		parts = append(parts, part)
	}
	return strings.Join(parts, ", ")
}
