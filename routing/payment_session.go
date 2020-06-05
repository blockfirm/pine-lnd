package routing

import (
	"fmt"

	"github.com/btcsuite/btclog"
	"github.com/lightningnetwork/lnd/build"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
)

// BlockPadding is used to increment the finalCltvDelta value for the last hop
// to prevent an HTLC being failed if some blocks are mined while it's in-flight.
const BlockPadding uint16 = 3

// noRouteError encodes a non-critical error encountered during path finding.
type noRouteError uint8

const (
	// errNoTlvPayload is returned when the destination hop does not support
	// a tlv payload.
	errNoTlvPayload noRouteError = iota

	// errNoPaymentAddr is returned when the destination hop does not
	// support payment addresses.
	errNoPaymentAddr

	// errNoPathFound is returned when a path to the target destination does
	// not exist in the graph.
	errNoPathFound

	// errInsufficientLocalBalance is returned when none of the local
	// channels have enough balance for the payment.
	errInsufficientBalance

	// errEmptyPaySession is returned when the empty payment session is
	// queried for a route.
	errEmptyPaySession

	// errUnknownRequiredFeature is returned when the destination node
	// requires an unknown feature.
	errUnknownRequiredFeature

	// errMissingDependentFeature is returned when the destination node
	// misses a feature that a feature that we require depends on.
	errMissingDependentFeature
)

var (
	// DefaultShardMinAmt is the default amount beyond which we won't try to
	// further split the payment if no route is found. It is the minimum
	// amount that we use as the shard size when splitting.
	DefaultShardMinAmt = lnwire.NewMSatFromSatoshis(10000)
)

// Error returns the string representation of the noRouteError
func (e noRouteError) Error() string {
	switch e {
	case errNoTlvPayload:
		return "destination hop doesn't understand new TLV payloads"

	case errNoPaymentAddr:
		return "destination hop doesn't understand payment addresses"

	case errNoPathFound:
		return "unable to find a path to destination"

	case errEmptyPaySession:
		return "empty payment session"

	case errInsufficientBalance:
		return "insufficient local balance"

	case errUnknownRequiredFeature:
		return "unknown required feature"

	case errMissingDependentFeature:
		return "missing dependent feature"

	default:
		return "unknown no-route error"
	}
}

// FailureReason converts a path finding error into a payment-level failure.
func (e noRouteError) FailureReason() channeldb.FailureReason {
	switch e {
	case
		errNoTlvPayload,
		errNoPaymentAddr,
		errNoPathFound,
		errEmptyPaySession,
		errUnknownRequiredFeature,
		errMissingDependentFeature:

		return channeldb.FailureReasonNoRoute

	case errInsufficientBalance:
		return channeldb.FailureReasonInsufficientBalance

	default:
		return channeldb.FailureReasonError
	}
}

// PaymentSession is used during SendPayment attempts to provide routes to
// attempt. It also defines methods to give the PaymentSession additional
// information learned during the previous attempts.
type PaymentSession interface {
	// RequestRoute returns the next route to attempt for routing the
	// specified HTLC payment to the target node. The returned route should
	// carry at most maxAmt to the target node, and pay at most feeLimit in
	// fees. It can carry less if the payment is MPP. The activeShards
	// argument should be set to instruct the payment session about the
	// number of in flight HTLCS for the payment, such that it can choose
	// splitting strategy accordingly.
	//
	// A noRouteError is returned if a non-critical error is encountered
	// during path finding.
	RequestRoute(maxAmt, feeLimit lnwire.MilliSatoshi,
		activeShards, height uint32) (*route.Route, error)
}

// paymentSession is used during an HTLC routings session to prune the local
// chain view in response to failures, and also report those failures back to
// MissionControl. The snapshot copied for this session will only ever grow,
// and will now be pruned after a decay like the main view within mission
// control. We do this as we want to avoid the case where we continually try a
// bad edge or route multiple times in a session. This can lead to an infinite
// loop if payment attempts take long enough. An additional set of edges can
// also be provided to assist in reaching the payment's destination.
type paymentSession struct {
	additionalEdges map[route.Vertex][]*channeldb.ChannelEdgePolicy

	getBandwidthHints func() (map[uint64]lnwire.MilliSatoshi, error)

	payment *LightningPayment

	empty bool

	pathFinder pathFinder

	getRoutingGraph func() (routingGraph, func(), error)

	// pathFindingConfig defines global parameters that control the
	// trade-off in path finding between fees and probabiity.
	pathFindingConfig PathFindingConfig

	missionControl MissionController

	// minShardAmt is the amount beyond which we won't try to further split
	// the payment if no route is found. If the maximum number of htlcs
	// specified in the payment is one, under no circumstances splitting
	// will happen and this value remains unused.
	minShardAmt lnwire.MilliSatoshi

	// log is a payment session-specific logger.
	log btclog.Logger
}

// newPaymentSession instantiates a new payment session.
func newPaymentSession(p *LightningPayment,
	getBandwidthHints func() (map[uint64]lnwire.MilliSatoshi, error),
	getRoutingGraph func() (routingGraph, func(), error),
	missionControl MissionController, pathFindingConfig PathFindingConfig) (
	*paymentSession, error) {

	edges, err := RouteHintsToEdges(p.RouteHints, p.Target)
	if err != nil {
		return nil, err
	}

	logPrefix := fmt.Sprintf("PaymentSession(%x):", p.PaymentHash)

	return &paymentSession{
		additionalEdges:   edges,
		getBandwidthHints: getBandwidthHints,
		payment:           p,
		pathFinder:        findPath,
		getRoutingGraph:   getRoutingGraph,
		pathFindingConfig: pathFindingConfig,
		missionControl:    missionControl,
		minShardAmt:       DefaultShardMinAmt,
		log:               build.NewPrefixLog(logPrefix, log),
	}, nil
}

// RequestRoute returns a route which is likely to be capable for successfully
// routing the specified HTLC payment to the target node. Initially the first
// set of paths returned from this method may encounter routing failure along
// the way, however as more payments are sent, mission control will start to
// build an up to date view of the network itself. With each payment a new area
// will be explored, which feeds into the recommendations made for routing.
//
// NOTE: This function is safe for concurrent access.
// NOTE: Part of the PaymentSession interface.
func (p *paymentSession) RequestRoute(maxAmt, feeLimit lnwire.MilliSatoshi,
	activeShards, height uint32) (*route.Route, error) {

	if p.empty {
		return nil, errEmptyPaySession
	}

	// Add BlockPadding to the finalCltvDelta so that the receiving node
	// does not reject the HTLC if some blocks are mined while it's in-flight.
	finalCltvDelta := p.payment.FinalCLTVDelta
	finalCltvDelta += BlockPadding

	// We need to subtract the final delta before passing it into path
	// finding. The optimal path is independent of the final cltv delta and
	// the path finding algorithm is unaware of this value.
	cltvLimit := p.payment.CltvLimit - uint32(finalCltvDelta)

	// TODO(roasbeef): sync logic amongst dist sys

	// Taking into account this prune view, we'll attempt to locate a path
	// to our destination, respecting the recommendations from
	// MissionControl.
	restrictions := &RestrictParams{
		ProbabilitySource:  p.missionControl.GetProbability,
		FeeLimit:           feeLimit,
		OutgoingChannelIDs: p.payment.OutgoingChannelIDs,
		LastHop:            p.payment.LastHop,
		CltvLimit:          cltvLimit,
		DestCustomRecords:  p.payment.DestCustomRecords,
		DestFeatures:       p.payment.DestFeatures,
		PaymentAddr:        p.payment.PaymentAddr,
	}

	finalHtlcExpiry := int32(height) + int32(finalCltvDelta)

	for {
		// We'll also obtain a set of bandwidthHints from the lower
		// layer for each of our outbound channels. This will allow the
		// path finding to skip any links that aren't active or just
		// don't have enough bandwidth to carry the payment. New
		// bandwidth hints are queried for every new path finding
		// attempt, because concurrent payments may change balances.
		bandwidthHints, err := p.getBandwidthHints()
		if err != nil {
			return nil, err
		}

		p.log.Debugf("pathfinding for amt=%v", maxAmt)

		// Get a routing graph.
		routingGraph, cleanup, err := p.getRoutingGraph()
		if err != nil {
			return nil, err
		}

		sourceVertex := routingGraph.sourceNode()

		// Find a route for the current amount.
		path, err := p.pathFinder(
			&graphParams{
				additionalEdges: p.additionalEdges,
				bandwidthHints:  bandwidthHints,
				graph:           routingGraph,
			},
			restrictions, &p.pathFindingConfig,
			sourceVertex, p.payment.Target,
			maxAmt, finalHtlcExpiry,
		)

		// Close routing graph.
		cleanup()

		switch {
		case err == errNoPathFound:
			// Don't split if this is a legacy payment without mpp
			// record.
			if p.payment.PaymentAddr == nil {
				p.log.Debugf("not splitting because payment " +
					"address is unspecified")

				return nil, errNoPathFound
			}

			// No splitting if this is the last shard.
			isLastShard := activeShards+1 >= p.payment.MaxParts
			if isLastShard {
				p.log.Debugf("not splitting because shard "+
					"limit %v has been reached",
					p.payment.MaxParts)

				return nil, errNoPathFound
			}

			// This is where the magic happens. If we can't find a
			// route, try it for half the amount.
			maxAmt /= 2

			// Put a lower bound on the minimum shard size.
			if maxAmt < p.minShardAmt {
				p.log.Debugf("not splitting because minimum "+
					"shard amount %v has been reached",
					p.minShardAmt)

				return nil, errNoPathFound
			}

			// Go pathfinding.
			continue

		// If there isn't enough local bandwidth, there is no point in
		// splitting. It won't be possible to create a complete set in
		// any case, but the sent out partial payments would be held by
		// the receiver until the mpp timeout.
		case err == errInsufficientBalance:
			p.log.Debug("not splitting because local balance " +
				"is insufficient")

			return nil, err

		case err != nil:
			return nil, err
		}

		// With the next candidate path found, we'll attempt to turn
		// this into a route by applying the time-lock and fee
		// requirements.
		route, err := newRoute(
			sourceVertex, path, height,
			finalHopParams{
				amt:         maxAmt,
				totalAmt:    p.payment.Amount,
				cltvDelta:   finalCltvDelta,
				records:     p.payment.DestCustomRecords,
				paymentAddr: p.payment.PaymentAddr,
			},
		)
		if err != nil {
			return nil, err
		}

		return route, err
	}
}
