// +build rpctest

package itest

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/lightningnetwork/lnd"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lntest"
	"github.com/lightningnetwork/lnd/routing/route"
)

// testSendToRouteMultiPath tests that we are able to successfully route a
// payment using multiple shards across different paths, by using SendToRoute.
func testSendToRouteMultiPath(net *lntest.NetworkHarness, t *harnessTest) {
	ctxb := context.Background()

	ctx := newMppTestContext(t, net)
	defer ctx.shutdownNodes()

	// To ensure the payment goes through seperate paths, we'll set a
	// channel size that can only carry one shard at a time. We'll divide
	// the payment into 3 shards.
	const (
		paymentAmt = btcutil.Amount(300000)
		shardAmt   = paymentAmt / 3
		chanAmt    = shardAmt * 3 / 2
	)

	// Set up a network with three different paths Alice <-> Bob.
	//              _ Eve _
	//             /       \
	// Alice -- Carol ---- Bob
	//      \              /
	//       \__ Dave ____/
	//
	ctx.openChannel(ctx.carol, ctx.bob, chanAmt)
	ctx.openChannel(ctx.dave, ctx.bob, chanAmt)
	ctx.openChannel(ctx.alice, ctx.dave, chanAmt)
	ctx.openChannel(ctx.eve, ctx.bob, chanAmt)
	ctx.openChannel(ctx.carol, ctx.eve, chanAmt)

	// Since the channel Alice-> Carol will have to carry two
	// shards, we make it larger.
	ctx.openChannel(ctx.alice, ctx.carol, chanAmt+shardAmt)

	defer ctx.closeChannels()

	ctx.waitForChannels()

	// Make Bob create an invoice for Alice to pay.
	payReqs, rHashes, invoices, err := createPayReqs(
		net.Bob, paymentAmt, 1,
	)
	if err != nil {
		t.Fatalf("unable to create pay reqs: %v", err)
	}

	rHash := rHashes[0]
	payReq := payReqs[0]

	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	decodeResp, err := net.Bob.DecodePayReq(
		ctxt, &lnrpc.PayReqString{PayReq: payReq},
	)
	if err != nil {
		t.Fatalf("decode pay req: %v", err)
	}

	payAddr := decodeResp.PaymentAddr

	// Helper function for Alice to build a route from pubkeys.
	buildRoute := func(amt btcutil.Amount, hops []*lntest.HarnessNode) (
		*lnrpc.Route, error) {

		rpcHops := make([][]byte, 0, len(hops))
		for _, hop := range hops {
			k := hop.PubKeyStr
			pubkey, err := route.NewVertexFromStr(k)
			if err != nil {
				return nil, fmt.Errorf("error parsing %v: %v",
					k, err)
			}
			rpcHops = append(rpcHops, pubkey[:])
		}

		req := &routerrpc.BuildRouteRequest{
			AmtMsat:        int64(amt * 1000),
			FinalCltvDelta: lnd.DefaultBitcoinTimeLockDelta,
			HopPubkeys:     rpcHops,
		}

		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		routeResp, err := net.Alice.RouterClient.BuildRoute(ctxt, req)
		if err != nil {
			return nil, err
		}

		return routeResp.Route, nil
	}

	// We'll send shards along three routes from Alice.
	sendRoutes := [][]*lntest.HarnessNode{
		{ctx.carol, ctx.bob},
		{ctx.dave, ctx.bob},
		{ctx.carol, ctx.eve, ctx.bob},
	}

	responses := make(chan *lnrpc.HTLCAttempt, len(sendRoutes))
	for _, hops := range sendRoutes {
		// Build a route for the specified hops.
		r, err := buildRoute(shardAmt, hops)
		if err != nil {
			t.Fatalf("unable to build route: %v", err)
		}

		// Set the MPP records to indicate this is a payment shard.
		hop := r.Hops[len(r.Hops)-1]
		hop.TlvPayload = true
		hop.MppRecord = &lnrpc.MPPRecord{
			PaymentAddr:  payAddr,
			TotalAmtMsat: int64(paymentAmt * 1000),
		}

		// Send the shard.
		sendReq := &routerrpc.SendToRouteRequest{
			PaymentHash: rHash,
			Route:       r,
		}

		// We'll send all shards in their own goroutine, since SendToRoute will
		// block as long as the payment is in flight.
		go func() {
			ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
			resp, err := net.Alice.RouterClient.SendToRouteV2(ctxt, sendReq)
			if err != nil {
				t.Fatalf("unable to send payment: %v", err)
			}

			responses <- resp
		}()
	}

	// Wait for all responses to be back, and check that they all
	// succeeded.
	for range sendRoutes {
		var resp *lnrpc.HTLCAttempt
		select {
		case resp = <-responses:
		case <-time.After(defaultTimeout):
			t.Fatalf("response not received")
		}

		if resp.Failure != nil {
			t.Fatalf("received payment failure : %v", resp.Failure)
		}

		// All shards should come back with the preimage.
		if !bytes.Equal(resp.Preimage, invoices[0].RPreimage) {
			t.Fatalf("preimage doesn't match")
		}
	}

	// assertNumHtlcs is a helper that checks the node's latest payment,
	// and asserts it was split into num shards.
	assertNumHtlcs := func(node *lntest.HarnessNode, num int) {
		req := &lnrpc.ListPaymentsRequest{
			IncludeIncomplete: true,
		}
		ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
		paymentsResp, err := node.ListPayments(ctxt, req)
		if err != nil {
			t.Fatalf("error when obtaining payments: %v",
				err)
		}

		payments := paymentsResp.Payments
		if len(payments) == 0 {
			t.Fatalf("no payments found")
		}

		payment := payments[len(payments)-1]
		htlcs := payment.Htlcs
		if len(htlcs) == 0 {
			t.Fatalf("no htlcs")
		}

		succeeded := 0
		for _, htlc := range htlcs {
			if htlc.Status == lnrpc.HTLCAttempt_SUCCEEDED {
				succeeded++
			}
		}

		if succeeded != num {
			t.Fatalf("expected %v succussful HTLCs, got %v", num,
				succeeded)
		}
	}

	// assertSettledInvoice checks that the invoice for the given payment
	// hash is settled, and has been paid using num HTLCs.
	assertSettledInvoice := func(node *lntest.HarnessNode, rhash []byte,
		num int) {

		found := false
		offset := uint64(0)
		for !found {
			ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
			invoicesResp, err := node.ListInvoices(
				ctxt, &lnrpc.ListInvoiceRequest{
					IndexOffset: offset,
				},
			)
			if err != nil {
				t.Fatalf("error when obtaining payments: %v",
					err)
			}

			if len(invoicesResp.Invoices) == 0 {
				break
			}

			for _, inv := range invoicesResp.Invoices {
				if !bytes.Equal(inv.RHash, rhash) {
					continue
				}

				// Assert that the amount paid to the invoice is
				// correct.
				if inv.AmtPaidSat != int64(paymentAmt) {
					t.Fatalf("incorrect payment amt for "+
						"invoicewant: %d, got %d",
						paymentAmt, inv.AmtPaidSat)
				}

				if inv.State != lnrpc.Invoice_SETTLED {
					t.Fatalf("Invoice not settled: %v",
						inv.State)
				}

				if len(inv.Htlcs) != num {
					t.Fatalf("expected invoice to be "+
						"settled with %v HTLCs, had %v",
						num, len(inv.Htlcs))
				}

				found = true
				break
			}

			offset = invoicesResp.LastIndexOffset
		}

		if !found {
			t.Fatalf("invoice not found")
		}
	}

	// Finally check that the payment shows up with three settled HTLCs in
	// Alice's list of payments...
	assertNumHtlcs(net.Alice, 3)

	// ...and in Bob's list of paid invoices.
	assertSettledInvoice(net.Bob, rHash, 3)
}

type mppTestContext struct {
	t   *harnessTest
	net *lntest.NetworkHarness

	// Keep a list of all our active channels.
	networkChans      []*lnrpc.ChannelPoint
	closeChannelFuncs []func()

	alice, bob, carol, dave, eve *lntest.HarnessNode
	nodes                        []*lntest.HarnessNode
}

func newMppTestContext(t *harnessTest,
	net *lntest.NetworkHarness) *mppTestContext {

	ctxb := context.Background()

	// Create a five-node context consisting of Alice, Bob and three new
	// nodes.
	carol, err := net.NewNode("carol", nil)
	if err != nil {
		t.Fatalf("unable to create carol: %v", err)
	}

	dave, err := net.NewNode("dave", nil)
	if err != nil {
		t.Fatalf("unable to create dave: %v", err)
	}

	eve, err := net.NewNode("eve", nil)
	if err != nil {
		t.Fatalf("unable to create eve: %v", err)
	}

	// Connect nodes to ensure propagation of channels.
	nodes := []*lntest.HarnessNode{net.Alice, net.Bob, carol, dave, eve}
	for i := 0; i < len(nodes); i++ {
		for j := i + 1; j < len(nodes); j++ {
			ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
			if err := net.EnsureConnected(ctxt, nodes[i], nodes[j]); err != nil {
				t.Fatalf("unable to connect nodes: %v", err)
			}
		}
	}

	ctx := mppTestContext{
		t:     t,
		net:   net,
		alice: net.Alice,
		bob:   net.Bob,
		carol: carol,
		dave:  dave,
		eve:   eve,
		nodes: nodes,
	}

	return &ctx
}

// openChannel is a helper to open a channel from->to.
func (c *mppTestContext) openChannel(from, to *lntest.HarnessNode, chanSize btcutil.Amount) {
	ctxb := context.Background()

	ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
	err := c.net.SendCoins(ctxt, btcutil.SatoshiPerBitcoin, from)
	if err != nil {
		c.t.Fatalf("unable to send coins : %v", err)
	}

	ctxt, _ = context.WithTimeout(ctxb, channelOpenTimeout)
	chanPoint := openChannelAndAssert(
		ctxt, c.t, c.net, from, to,
		lntest.OpenChannelParams{
			Amt: chanSize,
		},
	)

	c.closeChannelFuncs = append(c.closeChannelFuncs, func() {
		ctxt, _ := context.WithTimeout(ctxb, channelCloseTimeout)
		closeChannelAndAssert(
			ctxt, c.t, c.net, from, chanPoint, false,
		)
	})

	c.networkChans = append(c.networkChans, chanPoint)
}

func (c *mppTestContext) closeChannels() {
	for _, f := range c.closeChannelFuncs {
		f()
	}
}

func (c *mppTestContext) shutdownNodes() {
	shutdownAndAssert(c.net, c.t, c.carol)
	shutdownAndAssert(c.net, c.t, c.dave)
	shutdownAndAssert(c.net, c.t, c.eve)
}

func (c *mppTestContext) waitForChannels() {
	ctxb := context.Background()

	// Wait for all nodes to have seen all channels.
	for _, chanPoint := range c.networkChans {
		for _, node := range c.nodes {
			txid, err := lnd.GetChanPointFundingTxid(chanPoint)
			if err != nil {
				c.t.Fatalf("unable to get txid: %v", err)
			}
			point := wire.OutPoint{
				Hash:  *txid,
				Index: chanPoint.OutputIndex,
			}

			ctxt, _ := context.WithTimeout(ctxb, defaultTimeout)
			err = node.WaitForNetworkChannelOpen(ctxt, chanPoint)
			if err != nil {
				c.t.Fatalf("(%d): timeout waiting for "+
					"channel(%s) open: %v",
					node.NodeID, point, err)
			}
		}
	}
}
