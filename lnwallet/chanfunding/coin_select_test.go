package chanfunding

import (
	"encoding/hex"
	"regexp"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

var (
	p2wkhScript, _ = hex.DecodeString(
		"001411034bdcb6ccb7744fdfdeea958a6fb0b415a032",
	)
)

// fundingFee is a helper method that returns the fee estimate used for a tx
// with the given number of inputs and the optional change output. This matches
// the estimate done by the wallet.
func fundingFee(feeRate chainfee.SatPerKWeight, numInput int, // nolint:unparam
	change bool) btcutil.Amount {

	var weightEstimate input.TxWeightEstimator

	// All inputs.
	for i := 0; i < numInput; i++ {
		weightEstimate.AddP2WKHInput()
	}

	// The multisig funding output.
	weightEstimate.AddP2WSHOutput()

	// Optionally count a change output.
	if change {
		weightEstimate.AddP2WKHOutput()
	}

	totalWeight := int64(weightEstimate.Weight())
	return feeRate.FeeForWeight(totalWeight)
}

// TestCoinSelect tests that we pick coins adding up to the expected amount
// when creating a funding transaction, and that the calculated change is the
// expected amount.
//
// NOTE: coinSelect will always attempt to add a change output, so we must
// account for this in the tests.
func TestCoinSelect(t *testing.T) {
	t.Parallel()

	const feeRate = chainfee.SatPerKWeight(100)
	const dust = btcutil.Amount(100)

	type testCase struct {
		name        string
		outputValue btcutil.Amount
		coins       []Coin

		expectedInput  []btcutil.Amount
		expectedChange btcutil.Amount
		expectErr      bool
	}

	testCases := []testCase{
		{
			// We have 1.0 BTC available, and wants to send 0.5.
			// This will obviously lead to a change output of
			// almost 0.5 BTC.
			name: "big change",
			coins: []Coin{
				{
					TxOut: wire.TxOut{
						PkScript: p2wkhScript,
						Value:    1 * btcutil.SatoshiPerBitcoin,
					},
				},
			},
			outputValue: 0.5 * btcutil.SatoshiPerBitcoin,

			// The one and only input will be selected.
			expectedInput: []btcutil.Amount{
				1 * btcutil.SatoshiPerBitcoin,
			},
			// Change will be what's left minus the fee.
			expectedChange: 0.5*btcutil.SatoshiPerBitcoin - fundingFee(feeRate, 1, true),
		},
		{
			// We have 1 BTC available, and we want to send 1 BTC.
			// This should lead to an error, as we don't have
			// enough funds to pay the fee.
			name: "nothing left for fees",
			coins: []Coin{
				{
					TxOut: wire.TxOut{
						PkScript: p2wkhScript,
						Value:    1 * btcutil.SatoshiPerBitcoin,
					},
				},
			},
			outputValue: 1 * btcutil.SatoshiPerBitcoin,
			expectErr:   true,
		},
		{
			// We have a 1 BTC input, and want to create an output
			// as big as possible, such that the remaining change
			// will be dust.
			name: "dust change",
			coins: []Coin{
				{
					TxOut: wire.TxOut{
						PkScript: p2wkhScript,
						Value:    1 * btcutil.SatoshiPerBitcoin,
					},
				},
			},
			// We tune the output value by subtracting the expected
			// fee and a small dust amount.
			outputValue: 1*btcutil.SatoshiPerBitcoin - fundingFee(feeRate, 1, true) - dust,

			expectedInput: []btcutil.Amount{
				1 * btcutil.SatoshiPerBitcoin,
			},

			// Change will the dust.
			expectedChange: dust,
		},
		{
			// We have a 1 BTC input, and want to create an output
			// as big as possible, such that there is nothing left
			// for change.
			name: "no change",
			coins: []Coin{
				{
					TxOut: wire.TxOut{
						PkScript: p2wkhScript,
						Value:    1 * btcutil.SatoshiPerBitcoin,
					},
				},
			},
			// We tune the output value to be the maximum amount
			// possible, leaving just enough for fees.
			outputValue: 1*btcutil.SatoshiPerBitcoin - fundingFee(feeRate, 1, true),

			expectedInput: []btcutil.Amount{
				1 * btcutil.SatoshiPerBitcoin,
			},
			// We have just enough left to pay the fee, so there is
			// nothing left for change.
			// TODO(halseth): currently coinselect estimates fees
			// assuming a change output.
			expectedChange: 0,
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			selected, changeAmt, err := CoinSelect(
				feeRate, test.outputValue, test.coins,
			)
			if !test.expectErr && err != nil {
				t.Fatalf(err.Error())
			}

			if test.expectErr && err == nil {
				t.Fatalf("expected error")
			}

			// If we got an expected error, there is nothing more to test.
			if test.expectErr {
				return
			}

			// Check that the selected inputs match what we expect.
			if len(selected) != len(test.expectedInput) {
				t.Fatalf("expected %v inputs, got %v",
					len(test.expectedInput), len(selected))
			}

			for i, coin := range selected {
				if coin.Value != int64(test.expectedInput[i]) {
					t.Fatalf("expected input %v to have value %v, "+
						"had %v", i, test.expectedInput[i],
						coin.Value)
				}
			}

			// Assert we got the expected change amount.
			if changeAmt != test.expectedChange {
				t.Fatalf("expected %v change amt, got %v",
					test.expectedChange, changeAmt)
			}
		})
	}
}

// TestCoinSelectSubtractFees tests that we pick coins adding up to the
// expected amount when creating a funding transaction, and that a change
// output is created only when necessary.
func TestCoinSelectSubtractFees(t *testing.T) {
	t.Parallel()

	const feeRate = chainfee.SatPerKWeight(100)
	const highFeeRate = chainfee.SatPerKWeight(1000)
	const dustLimit = btcutil.Amount(1000)
	const dust = btcutil.Amount(100)

	// removeAmounts replaces any amounts in string with "<amt>".
	removeAmounts := func(s string) string {
		re := regexp.MustCompile(`[[:digit:]]+\.?[[:digit:]]*`)
		return re.ReplaceAllString(s, "<amt>")
	}

	type testCase struct {
		name       string
		highFee    bool
		spendValue btcutil.Amount
		coins      []Coin

		expectedInput      []btcutil.Amount
		expectedFundingAmt btcutil.Amount
		expectedChange     btcutil.Amount
		expectErr          string
	}

	testCases := []testCase{
		{
			// We have 1.0 BTC available, spend them all. This
			// should lead to a funding TX with one output, the
			// rest goes to fees.
			name: "spend all",
			coins: []Coin{
				{
					TxOut: wire.TxOut{
						PkScript: p2wkhScript,
						Value:    1 * btcutil.SatoshiPerBitcoin,
					},
				},
			},
			spendValue: 1 * btcutil.SatoshiPerBitcoin,

			// The one and only input will be selected.
			expectedInput: []btcutil.Amount{
				1 * btcutil.SatoshiPerBitcoin,
			},
			expectedFundingAmt: 1*btcutil.SatoshiPerBitcoin - fundingFee(feeRate, 1, false),
			expectedChange:     0,
		},
		{
			// We have 1.0 BTC available and spend half of it. This
			// should lead to a funding TX with a change output.
			name: "spend with change",
			coins: []Coin{
				{
					TxOut: wire.TxOut{
						PkScript: p2wkhScript,
						Value:    1 * btcutil.SatoshiPerBitcoin,
					},
				},
			},
			spendValue: 0.5 * btcutil.SatoshiPerBitcoin,

			// The one and only input will be selected.
			expectedInput: []btcutil.Amount{
				1 * btcutil.SatoshiPerBitcoin,
			},
			expectedFundingAmt: 0.5*btcutil.SatoshiPerBitcoin - fundingFee(feeRate, 1, true),
			expectedChange:     0.5 * btcutil.SatoshiPerBitcoin,
		},
		{
			// The total funds available is below the dust limit
			// after paying fees.
			name: "dust output",
			coins: []Coin{
				{
					TxOut: wire.TxOut{
						PkScript: p2wkhScript,
						Value:    int64(fundingFee(feeRate, 1, false) + dustLimit),
					},
				},
			},
			spendValue: fundingFee(feeRate, 1, false) + dust,

			expectErr: "output amount(<amt> BTC) after subtracting " +
				"fees(<amt> BTC) below dust limit(<amt> BTC)",
		},
		{
			// After subtracting fees, the resulting change output
			// is below the dust limit. The remainder should go
			// towards the funding output.
			name: "dust change",
			coins: []Coin{
				{
					TxOut: wire.TxOut{
						PkScript: p2wkhScript,
						Value:    1 * btcutil.SatoshiPerBitcoin,
					},
				},
			},
			spendValue: 1*btcutil.SatoshiPerBitcoin - dust,

			expectedInput: []btcutil.Amount{
				1 * btcutil.SatoshiPerBitcoin,
			},
			expectedFundingAmt: 1*btcutil.SatoshiPerBitcoin - fundingFee(feeRate, 1, false),
			expectedChange:     0,
		},
		{
			// We got just enough funds to create an output above the dust limit.
			name: "output right above dustlimit",
			coins: []Coin{
				{
					TxOut: wire.TxOut{
						PkScript: p2wkhScript,
						Value:    int64(fundingFee(feeRate, 1, false) + dustLimit + 1),
					},
				},
			},
			spendValue: fundingFee(feeRate, 1, false) + dustLimit + 1,

			expectedInput: []btcutil.Amount{
				fundingFee(feeRate, 1, false) + dustLimit + 1,
			},
			expectedFundingAmt: dustLimit + 1,
			expectedChange:     0,
		},
		{
			// Amount left is below dust limit after paying fee for
			// a change output, resulting in a no-change tx.
			name: "no amount to pay fee for change",
			coins: []Coin{
				{
					TxOut: wire.TxOut{
						PkScript: p2wkhScript,
						Value:    int64(fundingFee(feeRate, 1, false) + 2*(dustLimit+1)),
					},
				},
			},
			spendValue: fundingFee(feeRate, 1, false) + dustLimit + 1,

			expectedInput: []btcutil.Amount{
				fundingFee(feeRate, 1, false) + 2*(dustLimit+1),
			},
			expectedFundingAmt: 2 * (dustLimit + 1),
			expectedChange:     0,
		},
		{
			// If more than 20% of funds goes to fees, it should fail.
			name:    "high fee",
			highFee: true,
			coins: []Coin{
				{
					TxOut: wire.TxOut{
						PkScript: p2wkhScript,
						Value:    int64(5 * fundingFee(highFeeRate, 1, false)),
					},
				},
			},
			spendValue: 5 * fundingFee(highFeeRate, 1, false),

			expectErr: "fee <amt> BTC on total output value <amt> BTC",
		},
	}

	for _, test := range testCases {
		test := test

		t.Run(test.name, func(t *testing.T) {
			feeRate := feeRate
			if test.highFee {
				feeRate = highFeeRate
			}

			selected, localFundingAmt, changeAmt, err := CoinSelectSubtractFees(
				feeRate, test.spendValue, dustLimit, test.coins,
			)
			if err != nil {
				switch {
				case test.expectErr == "":
					t.Fatalf(err.Error())

				case test.expectErr != removeAmounts(err.Error()):
					t.Fatalf("expected error '%v', got '%v'",
						test.expectErr,
						removeAmounts(err.Error()))

				// If we got an expected error, there is
				// nothing more to test.
				default:
					return
				}
			}

			// Check that there was no expected error we missed.
			if test.expectErr != "" {
				t.Fatalf("expected error")
			}

			// Check that the selected inputs match what we expect.
			if len(selected) != len(test.expectedInput) {
				t.Fatalf("expected %v inputs, got %v",
					len(test.expectedInput), len(selected))
			}

			for i, coin := range selected {
				if coin.Value != int64(test.expectedInput[i]) {
					t.Fatalf("expected input %v to have value %v, "+
						"had %v", i, test.expectedInput[i],
						coin.Value)
				}
			}

			// Assert we got the expected change amount.
			if localFundingAmt != test.expectedFundingAmt {
				t.Fatalf("expected %v local funding amt, got %v",
					test.expectedFundingAmt, localFundingAmt)
			}
			if changeAmt != test.expectedChange {
				t.Fatalf("expected %v change amt, got %v",
					test.expectedChange, changeAmt)
			}
		})
	}
}
