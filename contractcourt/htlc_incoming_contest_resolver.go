package contractcourt

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/invoices"

	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd/lntypes"
)

// htlcIncomingContestResolver is a ContractResolver that's able to resolve an
// incoming HTLC that is still contested. An HTLC is still contested, if at the
// time of commitment broadcast, we don't know of the preimage for it yet, and
// it hasn't expired. In this case, we can resolve the HTLC if we learn of the
// preimage, otherwise the remote party will sweep it after it expires.
//
// TODO(roasbeef): just embed the other resolver?
type htlcIncomingContestResolver struct {
	// htlcExpiry is the absolute expiry of this incoming HTLC. We use this
	// value to determine if we can exit early as if the HTLC times out,
	// before we learn of the preimage then we can't claim it on chain
	// successfully.
	htlcExpiry uint32

	// circuitKey describes the incoming htlc that is being resolved.
	circuitKey channeldb.CircuitKey

	// htlcSuccessResolver is the inner resolver that may be utilized if we
	// learn of the preimage.
	htlcSuccessResolver
}

// Resolve attempts to resolve this contract. As we don't yet know of the
// preimage for the contract, we'll wait for one of two things to happen:
//
//   1. We learn of the preimage! In this case, we can sweep the HTLC incoming
//      and ensure that if this was a multi-hop HTLC we are made whole. In this
//      case, an additional ContractResolver will be returned to finish the
//      job.
//
//   2. The HTLC expires. If this happens, then the contract is fully resolved
//      as we have no remaining actions left at our disposal.
//
// NOTE: Part of the ContractResolver interface.
func (h *htlcIncomingContestResolver) Resolve() (ContractResolver, error) {
	// If we're already full resolved, then we don't have anything further
	// to do.
	if h.resolved {
		return nil, nil
	}

	// Register for block epochs. After registration, the current height
	// will be sent on the channel immediately.
	blockEpochs, err := h.Notifier.RegisterBlockEpochNtfn(nil)
	if err != nil {
		return nil, err
	}
	defer blockEpochs.Cancel()

	var currentHeight int32
	select {
	case newBlock, ok := <-blockEpochs.Epochs:
		if !ok {
			return nil, errResolverShuttingDown
		}
		currentHeight = newBlock.Height
	case <-h.Quit:
		return nil, errResolverShuttingDown
	}

	// We'll first check if this HTLC has been timed out, if so, we can
	// return now and mark ourselves as resolved. If we're past the point of
	// expiry of the HTLC, then at this point the sender can sweep it, so
	// we'll end our lifetime. Here we deliberately forego the chance that
	// the sender doesn't sweep and we already have or will learn the
	// preimage. Otherwise the resolver could potentially stay active
	// indefinitely and the channel will never close properly.
	if uint32(currentHeight) >= h.htlcExpiry {
		// TODO(roasbeef): should also somehow check if outgoing is
		// resolved or not
		//  * may need to hook into the circuit map
		//  * can't timeout before the outgoing has been

		log.Infof("%T(%v): HTLC has timed out (expiry=%v, height=%v), "+
			"abandoning", h, h.htlcResolution.ClaimOutpoint,
			h.htlcExpiry, currentHeight)
		h.resolved = true
		return nil, h.Checkpoint(h)
	}

	// tryApplyPreimage is a helper function that will populate our internal
	// resolver with the preimage we learn of. This should be called once
	// the preimage is revealed so the inner resolver can properly complete
	// its duties. The boolean return value indicates whether the preimage
	// was properly applied.
	applyPreimage := func(preimage lntypes.Preimage) error {
		// Sanity check to see if this preimage matches our htlc. At
		// this point it should never happen that it does not match.
		if !preimage.Matches(h.payHash) {
			return errors.New("preimage does not match hash")
		}

		// Update htlcResolution with the matching preimage.
		h.htlcResolution.Preimage = preimage

		log.Infof("%T(%v): extracted preimage=%v from beacon!", h,
			h.htlcResolution.ClaimOutpoint, preimage)

		// If this our commitment transaction, then we'll need to
		// populate the witness for the second-level HTLC transaction.
		if h.htlcResolution.SignedSuccessTx != nil {
			// Within the witness for the success transaction, the
			// preimage is the 4th element as it looks like:
			//
			//  * <sender sig> <recvr sig> <preimage> <witness script>
			//
			// We'll populate it within the witness, as since this
			// was a "contest" resolver, we didn't yet know of the
			// preimage.
			h.htlcResolution.SignedSuccessTx.TxIn[0].Witness[3] = preimage[:]
		}

		return nil
	}

	// If the HTLC hasn't expired yet, then we may still be able to claim
	// it if we learn of the pre-image, so we'll subscribe to the preimage
	// database to see if it turns up, or the HTLC times out.
	//
	// NOTE: This is done BEFORE opportunistically querying the db, to
	// ensure the preimage can't be delivered between querying and
	// registering for the preimage subscription.
	preimageSubscription := h.PreimageDB.SubscribeUpdates()
	defer preimageSubscription.CancelSubscription()

	// Define closure to process hodl events either direct or triggered by
	// later notifcation.
	processHodlEvent := func(e invoices.HodlEvent) (ContractResolver,
		error) {

		if e.Preimage == nil {
			log.Infof("%T(%v): Exit hop HTLC canceled "+
				"(expiry=%v, height=%v), abandoning", h,
				h.htlcResolution.ClaimOutpoint,
				h.htlcExpiry, currentHeight)

			h.resolved = true
			return nil, h.Checkpoint(h)
		}

		if err := applyPreimage(*e.Preimage); err != nil {
			return nil, err
		}

		return &h.htlcSuccessResolver, nil
	}

	// Create a buffered hodl chan to prevent deadlock.
	hodlChan := make(chan interface{}, 1)

	// Notify registry that we are potentially resolving as an exit hop
	// on-chain. If this HTLC indeed pays to an existing invoice, the
	// invoice registry will tell us what to do with the HTLC. This is
	// identical to HTLC resolution in the link.
	event, err := h.Registry.NotifyExitHopHtlc(
		h.payHash, h.htlcAmt, h.htlcExpiry, currentHeight,
		h.circuitKey, hodlChan, nil,
	)
	switch err {
	case channeldb.ErrInvoiceNotFound:
	case nil:
		defer h.Registry.HodlUnsubscribeAll(hodlChan)

		// Resolve the htlc directly if possible.
		if event != nil {
			return processHodlEvent(*event)
		}
	default:
		return nil, err
	}

	// With the epochs and preimage subscriptions initialized, we'll query
	// to see if we already know the preimage.
	preimage, ok := h.PreimageDB.LookupPreimage(h.payHash)
	if ok {
		// If we do, then this means we can claim the HTLC!  However,
		// we don't know how to ourselves, so we'll return our inner
		// resolver which has the knowledge to do so.
		if err := applyPreimage(preimage); err != nil {
			return nil, err
		}

		return &h.htlcSuccessResolver, nil
	}

	for {

		select {
		case preimage := <-preimageSubscription.WitnessUpdates:
			// We receive all new preimages, so we need to ignore
			// all except the preimage we are waiting for.
			if !preimage.Matches(h.payHash) {
				continue
			}

			if err := applyPreimage(preimage); err != nil {
				return nil, err
			}

			// We've learned of the preimage and this information
			// has been added to our inner resolver. We return it so
			// it can continue contract resolution.
			return &h.htlcSuccessResolver, nil

		case hodlItem := <-hodlChan:
			hodlEvent := hodlItem.(invoices.HodlEvent)

			return processHodlEvent(hodlEvent)

		case newBlock, ok := <-blockEpochs.Epochs:
			if !ok {
				return nil, errResolverShuttingDown
			}

			// If this new height expires the HTLC, then this means
			// we never found out the preimage, so we can mark
			// resolved and exit.
			newHeight := uint32(newBlock.Height)
			if newHeight >= h.htlcExpiry {
				log.Infof("%T(%v): HTLC has timed out "+
					"(expiry=%v, height=%v), abandoning", h,
					h.htlcResolution.ClaimOutpoint,
					h.htlcExpiry, currentHeight)
				h.resolved = true
				return nil, h.Checkpoint(h)
			}

		case <-h.Quit:
			return nil, errResolverShuttingDown
		}
	}
}

// report returns a report on the resolution state of the contract.
func (h *htlcIncomingContestResolver) report() *ContractReport {
	// No locking needed as these values are read-only.

	finalAmt := h.htlcAmt.ToSatoshis()
	if h.htlcResolution.SignedSuccessTx != nil {
		finalAmt = btcutil.Amount(
			h.htlcResolution.SignedSuccessTx.TxOut[0].Value,
		)
	}

	return &ContractReport{
		Outpoint:       h.htlcResolution.ClaimOutpoint,
		Incoming:       true,
		Amount:         finalAmt,
		MaturityHeight: h.htlcExpiry,
		LimboBalance:   finalAmt,
		Stage:          1,
	}
}

// Stop signals the resolver to cancel any current resolution processes, and
// suspend.
//
// NOTE: Part of the ContractResolver interface.
func (h *htlcIncomingContestResolver) Stop() {
	close(h.Quit)
}

// IsResolved returns true if the stored state in the resolve is fully
// resolved. In this case the target output can be forgotten.
//
// NOTE: Part of the ContractResolver interface.
func (h *htlcIncomingContestResolver) IsResolved() bool {
	return h.resolved
}

// Encode writes an encoded version of the ContractResolver into the passed
// Writer.
//
// NOTE: Part of the ContractResolver interface.
func (h *htlcIncomingContestResolver) Encode(w io.Writer) error {
	// We'll first write out the one field unique to this resolver.
	if err := binary.Write(w, endian, h.htlcExpiry); err != nil {
		return err
	}

	// Then we'll write out our internal resolver.
	return h.htlcSuccessResolver.Encode(w)
}

// Decode attempts to decode an encoded ContractResolver from the passed Reader
// instance, returning an active ContractResolver instance.
//
// NOTE: Part of the ContractResolver interface.
func (h *htlcIncomingContestResolver) Decode(r io.Reader) error {
	// We'll first read the one field unique to this resolver.
	if err := binary.Read(r, endian, &h.htlcExpiry); err != nil {
		return err
	}

	// Then we'll decode our internal resolver.
	return h.htlcSuccessResolver.Decode(r)
}

// AttachResolverKit should be called once a resolved is successfully decoded
// from its stored format. This struct delivers a generic tool kit that
// resolvers need to complete their duty.
//
// NOTE: Part of the ContractResolver interface.
func (h *htlcIncomingContestResolver) AttachResolverKit(r ResolverKit) {
	h.ResolverKit = r
}

// A compile time assertion to ensure htlcIncomingContestResolver meets the
// ContractResolver interface.
var _ ContractResolver = (*htlcIncomingContestResolver)(nil)
