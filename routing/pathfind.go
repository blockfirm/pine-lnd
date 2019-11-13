package routing

import (
	"container/heap"
	"fmt"
	"math"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/coreos/bbolt"

	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// HopLimit is the maximum number hops that is permissible as a route.
	// Any potential paths found that lie above this limit will be rejected
	// with an error. This value is computed using the current fixed-size
	// packet length of the Sphinx construction.
	HopLimit = 20

	// infinity is used as a starting distance in our shortest path search.
	infinity = math.MaxInt64

	// RiskFactorBillionths controls the influence of time lock delta
	// of a channel on route selection. It is expressed as billionths
	// of msat per msat sent through the channel per time lock delta
	// block. See edgeWeight function below for more details.
	// The chosen value is based on the previous incorrect weight function
	// 1 + timelock + fee * fee. In this function, the fee penalty
	// diminishes the time lock penalty for all but the smallest amounts.
	// To not change the behaviour of path finding too drastically, a
	// relatively small value is chosen which is still big enough to give
	// some effect with smaller time lock values. The value may need
	// tweaking and/or be made configurable in the future.
	RiskFactorBillionths = 15

	// estimatedNodeCount is used to preallocate the path finding structures
	// to avoid resizing and copies. It should be number on the same order as
	// the number of active nodes in the network.
	estimatedNodeCount = 10000
)

// pathFinder defines the interface of a path finding algorithm.
type pathFinder = func(g *graphParams, r *RestrictParams,
	cfg *PathFindingConfig, source, target route.Vertex,
	amt lnwire.MilliSatoshi) ([]*channeldb.ChannelEdgePolicy, error)

var (
	// DefaultPaymentAttemptPenalty is the virtual cost in path finding weight
	// units of executing a payment attempt that fails. It is used to trade
	// off potentially better routes against their probability of
	// succeeding.
	DefaultPaymentAttemptPenalty = lnwire.NewMSatFromSatoshis(100)

	// DefaultMinRouteProbability is the default minimum probability for routes
	// returned from findPath.
	DefaultMinRouteProbability = float64(0.01)

	// DefaultAprioriHopProbability is the default a priori probability for
	// a hop.
	DefaultAprioriHopProbability = float64(0.6)
)

// edgePolicyWithSource is a helper struct to keep track of the source node
// of a channel edge. ChannelEdgePolicy only contains to destination node
// of the edge.
type edgePolicyWithSource struct {
	sourceNode route.Vertex
	edge       *channeldb.ChannelEdgePolicy
}

// newRoute returns a fully valid route between the source and target that's
// capable of supporting a payment of `amtToSend` after fees are fully
// computed. If the route is too long, or the selected path cannot support the
// fully payment including fees, then a non-nil error is returned.
//
// NOTE: The passed slice of ChannelHops MUST be sorted in forward order: from
// the source to the target node of the path finding attempt.
func newRoute(amtToSend lnwire.MilliSatoshi, sourceVertex route.Vertex,
	pathEdges []*channeldb.ChannelEdgePolicy, currentHeight uint32,
	finalCLTVDelta uint16,
	finalDestRecords []tlv.Record) (*route.Route, error) {

	var (
		hops []*route.Hop

		// totalTimeLock will accumulate the cumulative time lock
		// across the entire route. This value represents how long the
		// sender will need to wait in the *worst* case.
		totalTimeLock = currentHeight

		// nextIncomingAmount is the amount that will need to flow into
		// the *next* hop. Since we're going to be walking the route
		// backwards below, this next hop gets closer and closer to the
		// sender of the payment.
		nextIncomingAmount lnwire.MilliSatoshi
	)

	pathLength := len(pathEdges)
	for i := pathLength - 1; i >= 0; i-- {
		// Now we'll start to calculate the items within the per-hop
		// payload for the hop this edge is leading to.
		edge := pathEdges[i]

		// If this is the last hop, then the hop payload will contain
		// the exact amount. In BOLT #4: Onion Routing
		// Protocol / "Payload for the Last Node", this is detailed.
		amtToForward := amtToSend

		// Fee is not part of the hop payload, but only used for
		// reporting through RPC. Set to zero for the final hop.
		fee := lnwire.MilliSatoshi(0)

		// If the current hop isn't the last hop, then add enough funds
		// to pay for transit over the next link.
		if i != len(pathEdges)-1 {
			// The amount that the current hop needs to forward is
			// equal to the incoming amount of the next hop.
			amtToForward = nextIncomingAmount

			// The fee that needs to be paid to the current hop is
			// based on the amount that this hop needs to forward
			// and its policy for the outgoing channel. This policy
			// is stored as part of the incoming channel of
			// the next hop.
			fee = pathEdges[i+1].ComputeFee(amtToForward)
		}

		// If this is the last hop, then for verification purposes, the
		// value of the outgoing time-lock should be _exactly_ the
		// absolute time out they'd expect in the HTLC.
		var outgoingTimeLock uint32
		if i == len(pathEdges)-1 {
			// As this is the last hop, we'll use the specified
			// final CLTV delta value instead of the value from the
			// last link in the route.
			totalTimeLock += uint32(finalCLTVDelta)

			outgoingTimeLock = currentHeight + uint32(finalCLTVDelta)
		} else {
			// Next, increment the total timelock of the entire
			// route such that each hops time lock increases as we
			// walk backwards in the route, using the delta of the
			// previous hop.
			delta := uint32(pathEdges[i+1].TimeLockDelta)
			totalTimeLock += delta

			// Otherwise, the value of the outgoing time-lock will
			// be the value of the time-lock for the _outgoing_
			// HTLC, so we factor in their specified grace period
			// (time lock delta).
			outgoingTimeLock = totalTimeLock - delta
		}

		// Since we're traversing the path backwards atm, we prepend
		// each new hop such that, the final slice of hops will be in
		// the forwards order.
		currentHop := &route.Hop{
			PubKeyBytes:      edge.Node.PubKeyBytes,
			ChannelID:        edge.ChannelID,
			AmtToForward:     amtToForward,
			OutgoingTimeLock: outgoingTimeLock,
			LegacyPayload:    true,
		}

		// We start out above by assuming that this node needs the
		// legacy payload, as if we don't have the full
		// NodeAnnouncement information for this node, then we can't
		// assume it knows the latest features. If we do have a feature
		// vector for this node, then we'll update the info now.
		if edge.Node.Features != nil {
			features := edge.Node.Features
			currentHop.LegacyPayload = !features.HasFeature(
				lnwire.TLVOnionPayloadOptional,
			)
		}

		// If this is the last hop, then we'll populate any TLV records
		// destined for it.
		if i == len(pathEdges)-1 && len(finalDestRecords) != 0 {
			currentHop.TLVRecords = finalDestRecords
		}

		hops = append([]*route.Hop{currentHop}, hops...)

		// Finally, we update the amount that needs to flow into the
		// *next* hop, which is the amount this hop needs to forward,
		// accounting for the fee that it takes.
		nextIncomingAmount = amtToForward + fee
	}

	// With the base routing data expressed as hops, build the full route
	newRoute, err := route.NewRouteFromHops(
		nextIncomingAmount, totalTimeLock, route.Vertex(sourceVertex),
		hops,
	)
	if err != nil {
		return nil, err
	}

	return newRoute, nil
}

// edgeWeight computes the weight of an edge. This value is used when searching
// for the shortest path within the channel graph between two nodes. Weight is
// is the fee itself plus a time lock penalty added to it. This benefits
// channels with shorter time lock deltas and shorter (hops) routes in general.
// RiskFactor controls the influence of time lock on route selection. This is
// currently a fixed value, but might be configurable in the future.
func edgeWeight(lockedAmt lnwire.MilliSatoshi, fee lnwire.MilliSatoshi,
	timeLockDelta uint16) int64 {
	// timeLockPenalty is the penalty for the time lock delta of this channel.
	// It is controlled by RiskFactorBillionths and scales proportional
	// to the amount that will pass through channel. Rationale is that it if
	// a twice as large amount gets locked up, it is twice as bad.
	timeLockPenalty := int64(lockedAmt) * int64(timeLockDelta) *
		RiskFactorBillionths / 1000000000

	return int64(fee) + timeLockPenalty
}

// graphParams wraps the set of graph parameters passed to findPath.
type graphParams struct {
	// tx can be set to an existing db transaction. If not set, a new
	// transaction will be started.
	tx *bbolt.Tx

	// graph is the ChannelGraph to be used during path finding.
	graph *channeldb.ChannelGraph

	// additionalEdges is an optional set of edges that should be
	// considered during path finding, that is not already found in the
	// channel graph.
	additionalEdges map[route.Vertex][]*channeldb.ChannelEdgePolicy

	// bandwidthHints is an optional map from channels to bandwidths that
	// can be populated if the caller has a better estimate of the current
	// channel bandwidth than what is found in the graph. If set, it will
	// override the capacities and disabled flags found in the graph for
	// local channels when doing path finding. In particular, it should be
	// set to the current available sending bandwidth for active local
	// channels, and 0 for inactive channels.
	bandwidthHints map[uint64]lnwire.MilliSatoshi
}

// RestrictParams wraps the set of restrictions passed to findPath that the
// found path must adhere to.
type RestrictParams struct {
	// ProbabilitySource is a callback that is expected to return the
	// success probability of traversing the channel from the node.
	ProbabilitySource func(route.Vertex, route.Vertex,
		lnwire.MilliSatoshi) float64

	// FeeLimit is a maximum fee amount allowed to be used on the path from
	// the source to the target.
	FeeLimit lnwire.MilliSatoshi

	// OutgoingChannelID is the channel that needs to be taken to the first
	// hop. If nil, any channel may be used.
	OutgoingChannelID *uint64

	// CltvLimit is the maximum time lock of the route excluding the final
	// ctlv. After path finding is complete, the caller needs to increase
	// all cltv expiry heights with the required final cltv delta.
	CltvLimit uint32

	// DestPayloadTLV should be set to true if we need to drop off a TLV
	// payload at the final hop in order to properly complete this payment
	// attempt.
	DestPayloadTLV bool
}

// PathFindingConfig defines global parameters that control the trade-off in
// path finding between fees and probabiity.
type PathFindingConfig struct {
	// PaymentAttemptPenalty is the virtual cost in path finding weight
	// units of executing a payment attempt that fails. It is used to trade
	// off potentially better routes against their probability of
	// succeeding.
	PaymentAttemptPenalty lnwire.MilliSatoshi

	// MinProbability defines the minimum success probability of the
	// returned route.
	MinProbability float64
}

// findPath attempts to find a path from the source node within the
// ChannelGraph to the target node that's capable of supporting a payment of
// `amt` value. The current approach implemented is modified version of
// Dijkstra's algorithm to find a single shortest path between the source node
// and the destination. The distance metric used for edges is related to the
// time-lock+fee costs along a particular edge. If a path is found, this
// function returns a slice of ChannelHop structs which encoded the chosen path
// from the target to the source. The search is performed backwards from
// destination node back to source. This is to properly accumulate fees
// that need to be paid along the path and accurately check the amount
// to forward at every node against the available bandwidth.
func findPath(g *graphParams, r *RestrictParams, cfg *PathFindingConfig,
	source, target route.Vertex, amt lnwire.MilliSatoshi) (
	[]*channeldb.ChannelEdgePolicy, error) {

	// Pathfinding can be a significant portion of the total payment
	// latency, especially on low-powered devices. Log several metrics to
	// aid in the analysis performance problems in this area.
	start := time.Now()
	nodesVisited := 0
	edgesExpanded := 0
	defer func() {
		timeElapsed := time.Since(start)
		log.Debugf("Pathfinding perf metrics: nodes=%v, edges=%v, "+
			"time=%v", nodesVisited, edgesExpanded, timeElapsed)
	}()

	var err error
	tx := g.tx
	if tx == nil {
		tx, err = g.graph.Database().Begin(false)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
	}

	if r.DestPayloadTLV {
		// Check if the target has TLV enabled

		targetKey, err := btcec.ParsePubKey(target[:], btcec.S256())
		if err != nil {
			return nil, err
		}

		targetNode, err := g.graph.FetchLightningNode(targetKey)
		if err != nil {
			return nil, err
		}

		if targetNode.Features != nil {
			supportsTLV := targetNode.Features.HasFeature(
				lnwire.TLVOnionPayloadOptional,
			)
			if !supportsTLV {
				return nil, fmt.Errorf("destination hop doesn't " +
					"understand new TLV paylods")
			}
		}
	}

	// First we'll initialize an empty heap which'll help us to quickly
	// locate the next edge we should visit next during our graph
	// traversal.
	nodeHeap := newDistanceHeap(estimatedNodeCount)

	// Holds the current best distance for a given node.
	distance := make(map[route.Vertex]*nodeWithDist, estimatedNodeCount)

	additionalEdgesWithSrc := make(map[route.Vertex][]*edgePolicyWithSource)
	for vertex, outgoingEdgePolicies := range g.additionalEdges {

		// Build reverse lookup to find incoming edges. Needed because
		// search is taken place from target to source.
		for _, outgoingEdgePolicy := range outgoingEdgePolicies {
			toVertex := outgoingEdgePolicy.Node.PubKeyBytes
			incomingEdgePolicy := &edgePolicyWithSource{
				sourceNode: vertex,
				edge:       outgoingEdgePolicy,
			}

			additionalEdgesWithSrc[toVertex] =
				append(additionalEdgesWithSrc[toVertex],
					incomingEdgePolicy)
		}
	}

	// We can't always assume that the end destination is publicly
	// advertised to the network so we'll manually include the target node.
	// The target node charges no fee. Distance is set to 0, because this
	// is the starting point of the graph traversal. We are searching
	// backwards to get the fees first time right and correctly match
	// channel bandwidth.
	distance[target] = &nodeWithDist{
		dist:            0,
		weight:          0,
		node:            target,
		amountToReceive: amt,
		incomingCltv:    0,
		probability:     1,
	}

	// processEdge is a helper closure that will be used to make sure edges
	// satisfy our specific requirements.
	processEdge := func(fromVertex route.Vertex,
		edge *channeldb.ChannelEdgePolicy, toNodeDist *nodeWithDist) {

		edgesExpanded++

		// Calculate amount that the candidate node would have to sent
		// out.
		amountToSend := toNodeDist.amountToReceive

		// Request the success probability for this edge.
		edgeProbability := r.ProbabilitySource(
			fromVertex, toNodeDist.node, amountToSend,
		)

		log.Trace(newLogClosure(func() string {
			return fmt.Sprintf("path finding probability: fromnode=%v,"+
				" tonode=%v, probability=%v", fromVertex, toNodeDist.node,
				edgeProbability)
		}))

		// If the probability is zero, there is no point in trying.
		if edgeProbability == 0 {
			return
		}

		// Compute fee that fromVertex is charging. It is based on the
		// amount that needs to be sent to the next node in the route.
		//
		// Source node has no predecessor to pay a fee. Therefore set
		// fee to zero, because it should not be included in the fee
		// limit check and edge weight.
		//
		// Also determine the time lock delta that will be added to the
		// route if fromVertex is selected. If fromVertex is the source
		// node, no additional timelock is required.
		var fee lnwire.MilliSatoshi
		var timeLockDelta uint16
		if fromVertex != source {
			fee = edge.ComputeFee(amountToSend)
			timeLockDelta = edge.TimeLockDelta
		}

		incomingCltv := toNodeDist.incomingCltv +
			uint32(timeLockDelta)

		// Check that we are within our CLTV limit.
		if incomingCltv > r.CltvLimit {
			return
		}

		// amountToReceive is the amount that the node that is added to
		// the distance map needs to receive from a (to be found)
		// previous node in the route. That previous node will need to
		// pay the amount that this node forwards plus the fee it
		// charges.
		amountToReceive := amountToSend + fee

		// Check if accumulated fees would exceed fee limit when this
		// node would be added to the path.
		totalFee := amountToReceive - amt
		if totalFee > r.FeeLimit {
			return
		}

		// Calculate total probability of successfully reaching target
		// by multiplying the probabilities. Both this edge and the rest
		// of the route must succeed.
		probability := toNodeDist.probability * edgeProbability

		// If the probability is below the specified lower bound, we can
		// abandon this direction. Adding further nodes can only lower
		// the probability more.
		if probability < cfg.MinProbability {
			return
		}

		// By adding fromVertex in the route, there will be an extra
		// weight composed of the fee that this node will charge and
		// the amount that will be locked for timeLockDelta blocks in
		// the HTLC that is handed out to fromVertex.
		weight := edgeWeight(amountToReceive, fee, timeLockDelta)

		// Compute the tentative weight to this new channel/edge
		// which is the weight from our toNode to the target node
		// plus the weight of this edge.
		tempWeight := toNodeDist.weight + weight

		// Add an extra factor to the weight to take into account the
		// probability.
		tempDist := getProbabilityBasedDist(
			tempWeight, probability,
			int64(cfg.PaymentAttemptPenalty),
		)

		// If the current best route is better than this candidate
		// route, return. It is important to also return if the distance
		// is equal, because otherwise the algorithm could run into an
		// endless loop.
		current, ok := distance[fromVertex]
		if ok && tempDist >= current.dist {
			return
		}

		// Every edge should have a positive time lock delta. If we
		// encounter a zero delta, log a warning line.
		if edge.TimeLockDelta == 0 {
			log.Warnf("Channel %v has zero cltv delta",
				edge.ChannelID)
		}

		// All conditions are met and this new tentative distance is
		// better than the current best known distance to this node.
		// The new better distance is recorded, and also our "next hop"
		// map is populated with this edge.
		withDist := &nodeWithDist{
			dist:            tempDist,
			weight:          tempWeight,
			node:            fromVertex,
			amountToReceive: amountToReceive,
			incomingCltv:    incomingCltv,
			probability:     probability,
			nextHop:         edge,
		}
		distance[fromVertex] = withDist

		// Either push withDist onto the heap if the node
		// represented by fromVertex is not already on the heap OR adjust
		// its position within the heap via heap.Fix.
		nodeHeap.PushOrFix(withDist)
	}

	// TODO(roasbeef): also add path caching
	//  * similar to route caching, but doesn't factor in the amount

	// To start, our target node will the sole item within our distance
	// heap.
	heap.Push(&nodeHeap, distance[target])

	for nodeHeap.Len() != 0 {
		nodesVisited++

		// Fetch the node within the smallest distance from our source
		// from the heap.
		partialPath := heap.Pop(&nodeHeap).(*nodeWithDist)
		pivot := partialPath.node

		// If we've reached our source (or we don't have any incoming
		// edges), then we're done here and can exit the graph
		// traversal early.
		if pivot == source {
			break
		}

		// Create unified policies for all incoming connections.
		u := newUnifiedPolicies(source, pivot, r.OutgoingChannelID)

		err := u.addGraphPolicies(g.graph, tx)
		if err != nil {
			return nil, err
		}

		for _, reverseEdge := range additionalEdgesWithSrc[pivot] {
			u.addPolicy(reverseEdge.sourceNode, reverseEdge.edge, 0)
		}

		amtToSend := partialPath.amountToReceive

		// Expand all connections using the optimal policy for each
		// connection.
		for fromNode, unifiedPolicy := range u.policies {
			policy := unifiedPolicy.getPolicy(
				amtToSend, g.bandwidthHints,
			)

			if policy == nil {
				continue
			}

			// Check if this candidate node is better than what we
			// already have.
			processEdge(fromNode, policy, partialPath)
		}
	}

	// Use the distance map to unravel the forward path from source to
	// target.
	var pathEdges []*channeldb.ChannelEdgePolicy
	currentNode := source
	for currentNode != target { // TODO(roasbeef): assumes no cycles
		// Determine the next hop forward using the next map.
		currentNodeWithDist, ok := distance[currentNode]
		if !ok {
			// If the node doesnt have a next hop it means we didn't find a path.
			return nil, newErrf(ErrNoPathFound, "unable to find a "+
				"path to destination")
		}

		// Add the next hop to the list of path edges.
		pathEdges = append(pathEdges, currentNodeWithDist.nextHop)

		// Advance current node.
		currentNode = currentNodeWithDist.nextHop.Node.PubKeyBytes
	}

	// The route is invalid if it spans more than 20 hops. The current
	// Sphinx (onion routing) implementation can only encode up to 20 hops
	// as the entire packet is fixed size. If this route is more than 20
	// hops, then it's invalid.
	numEdges := len(pathEdges)
	if numEdges > HopLimit {
		return nil, newErr(ErrMaxHopsExceeded, "potential path has "+
			"too many hops")
	}

	log.Debugf("Found route: probability=%v, hops=%v, fee=%v\n",
		distance[source].probability, numEdges,
		distance[source].amountToReceive-amt)

	return pathEdges, nil
}

// getProbabilityBasedDist converts a weight into a distance that takes into
// account the success probability and the (virtual) cost of a failed payment
// attempt.
//
// Derivation:
//
// Suppose there are two routes A and B with fees Fa and Fb and success
// probabilities Pa and Pb.
//
// Is the expected cost of trying route A first and then B lower than trying the
// other way around?
//
// The expected cost of A-then-B is: Pa*Fa + (1-Pa)*Pb*(c+Fb)
//
// The expected cost of B-then-A is: Pb*Fb + (1-Pb)*Pa*(c+Fa)
//
// In these equations, the term representing the case where both A and B fail is
// left out because its value would be the same in both cases.
//
// Pa*Fa + (1-Pa)*Pb*(c+Fb) < Pb*Fb + (1-Pb)*Pa*(c+Fa)
//
// Pa*Fa + Pb*c + Pb*Fb - Pa*Pb*c - Pa*Pb*Fb < Pb*Fb + Pa*c + Pa*Fa - Pa*Pb*c - Pa*Pb*Fa
//
// Removing terms that cancel out:
// Pb*c - Pa*Pb*Fb < Pa*c - Pa*Pb*Fa
//
// Divide by Pa*Pb:
// c/Pa - Fb < c/Pb - Fa
//
// Move terms around:
// Fa + c/Pa < Fb + c/Pb
//
// So the value of F + c/P can be used to compare routes.
func getProbabilityBasedDist(weight int64, probability float64, penalty int64) int64 {
	// Clamp probability to prevent overflow.
	const minProbability = 0.00001

	if probability < minProbability {
		return infinity
	}

	return weight + int64(float64(penalty)/probability)
}
