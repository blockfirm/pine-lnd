package contractcourt

import (
	"io"

	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/htlcswitch/hop"
	"github.com/lightningnetwork/lnd/invoices"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwire"
)

// Registry is an interface which represents the invoice registry.
type Registry interface {
	// LookupInvoice attempts to look up an invoice according to its 32
	// byte payment hash.
	LookupInvoice(lntypes.Hash) (channeldb.Invoice, error)

	// NotifyExitHopHtlc attempts to mark an invoice as settled. If the
	// invoice is a debug invoice, then this method is a noop as debug
	// invoices are never fully settled. The return value describes how the
	// htlc should be resolved. If the htlc cannot be resolved immediately,
	// the resolution is sent on the passed in hodlChan later.
	NotifyExitHopHtlc(payHash lntypes.Hash, paidAmount lnwire.MilliSatoshi,
		expiry uint32, currentHeight int32,
		circuitKey channeldb.CircuitKey, hodlChan chan<- interface{},
		payload invoices.Payload) (*invoices.HodlEvent, error)

	// HodlUnsubscribeAll unsubscribes from all hodl events.
	HodlUnsubscribeAll(subscriber chan<- interface{})
}

// OnionProcessor is an interface used to decode onion blobs.
type OnionProcessor interface {
	// ReconstructHopIterator attempts to decode a valid sphinx packet from
	// the passed io.Reader instance.
	ReconstructHopIterator(r io.Reader, rHash []byte) (hop.Iterator, error)
}
