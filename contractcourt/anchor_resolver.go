package contractcourt

import (
	"errors"
	"io"
	"sync"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/sweep"
)

// anchorResolver is a resolver that will attempt to sweep our anchor output.
type anchorResolver struct {
	// anchorSignDescriptor contains the information that is required to
	// sweep the anchor.
	anchorSignDescriptor input.SignDescriptor

	// anchor is the outpoint on the commitment transaction.
	anchor wire.OutPoint

	// resolved reflects if the contract has been fully resolved or not.
	resolved bool

	// broadcastHeight is the height that the original contract was
	// broadcast to the main-chain at. We'll use this value to bound any
	// historical queries to the chain for spends/confirmations.
	broadcastHeight uint32

	// chanPoint is the channel point of the original contract.
	chanPoint wire.OutPoint

	// currentReport stores the current state of the resolver for reporting
	// over the rpc interface.
	currentReport ContractReport

	// reportLock prevents concurrent access to the resolver report.
	reportLock sync.Mutex

	contractResolverKit
}

// newAnchorResolver instantiates a new anchor resolver.
func newAnchorResolver(anchorSignDescriptor input.SignDescriptor,
	anchor wire.OutPoint, broadcastHeight uint32,
	chanPoint wire.OutPoint, resCfg ResolverConfig) *anchorResolver {

	amt := btcutil.Amount(anchorSignDescriptor.Output.Value)

	report := ContractReport{
		Outpoint:         anchor,
		Type:             ReportOutputAnchor,
		Amount:           amt,
		LimboBalance:     amt,
		RecoveredBalance: 0,
	}

	r := &anchorResolver{
		contractResolverKit:  *newContractResolverKit(resCfg),
		anchorSignDescriptor: anchorSignDescriptor,
		anchor:               anchor,
		broadcastHeight:      broadcastHeight,
		chanPoint:            chanPoint,
		currentReport:        report,
	}

	r.initLogger(r)

	return r
}

// ResolverKey returns an identifier which should be globally unique for this
// particular resolver within the chain the original contract resides within.
func (c *anchorResolver) ResolverKey() []byte {
	// The anchor resolver is stateless and doesn't need a database key.
	return nil
}

// Resolve offers the anchor output to the sweeper and waits for it to be swept.
func (c *anchorResolver) Resolve() (ContractResolver, error) {
	// Attempt to update the sweep parameters to the post-confirmation
	// situation. We don't want to force sweep anymore, because the anchor
	// lost its special purpose to get the commitment confirmed. It is just
	// an output that we want to sweep only if it is economical to do so.
	relayFeeRate := c.Sweeper.RelayFeePerKW()

	resultChan, err := c.Sweeper.UpdateParams(
		c.anchor,
		sweep.ParamsUpdate{
			Fee: sweep.FeePreference{
				FeeRate: relayFeeRate,
			},
			Force: false,
		},
	)

	// After a restart or when the remote force closes, the sweeper is not
	// yet aware of the anchor. In that case, offer it as a new input to the
	// sweeper. An exclusive group is not necessary anymore, because we know
	// that this is the only anchor that can be swept.
	if err == lnwallet.ErrNotMine {
		anchorInput := input.MakeBaseInput(
			&c.anchor,
			input.CommitmentAnchor,
			&c.anchorSignDescriptor,
			c.broadcastHeight,
		)

		resultChan, err = c.Sweeper.SweepInput(
			&anchorInput,
			sweep.Params{
				Fee: sweep.FeePreference{
					FeeRate: relayFeeRate,
				},
			},
		)
		if err != nil {
			return nil, err
		}
	}

	var anchorRecovered bool
	select {
	case sweepRes := <-resultChan:
		switch sweepRes.Err {

		// Anchor was swept successfully.
		case nil:
			c.log.Debugf("anchor swept by tx %v",
				sweepRes.Tx.TxHash())

			anchorRecovered = true

		// Anchor was swept by someone else. This is possible after the
		// 16 block csv lock.
		case sweep.ErrRemoteSpend:
			c.log.Warnf("our anchor spent by someone else")

		// The sweeper gave up on sweeping the anchor. This happens
		// after the maximum number of sweep attempts has been reached.
		// See sweep.DefaultMaxSweepAttempts. Sweep attempts are
		// interspaced with random delays picked from a range that
		// increases exponentially.
		//
		// We consider the anchor as being lost.
		case sweep.ErrTooManyAttempts:
			c.log.Warnf("anchor sweep abandoned")

		// An unexpected error occurred.
		default:
			c.log.Errorf("unable to sweep anchor: %v", sweepRes.Err)

			return nil, sweepRes.Err
		}

	case <-c.quit:
		return nil, errResolverShuttingDown
	}

	// Update report to reflect that funds are no longer in limbo.
	c.reportLock.Lock()
	if anchorRecovered {
		c.currentReport.RecoveredBalance = c.currentReport.LimboBalance
	}
	c.currentReport.LimboBalance = 0
	c.reportLock.Unlock()

	c.resolved = true
	return nil, nil
}

// Stop signals the resolver to cancel any current resolution processes, and
// suspend.
//
// NOTE: Part of the ContractResolver interface.
func (c *anchorResolver) Stop() {
	close(c.quit)
}

// IsResolved returns true if the stored state in the resolve is fully
// resolved. In this case the target output can be forgotten.
//
// NOTE: Part of the ContractResolver interface.
func (c *anchorResolver) IsResolved() bool {
	return c.resolved
}

// report returns a report on the resolution state of the contract.
func (c *anchorResolver) report() *ContractReport {
	c.reportLock.Lock()
	defer c.reportLock.Unlock()

	reportCopy := c.currentReport
	return &reportCopy
}

func (c *anchorResolver) Encode(w io.Writer) error {
	return errors.New("serialization not supported")
}

// A compile time assertion to ensure anchorResolver meets the
// ContractResolver interface.
var _ ContractResolver = (*anchorResolver)(nil)
