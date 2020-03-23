package invoices

import (
	"testing"
	"time"

	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/lntypes"
)

// invoiceExpiryWatcherTest holds a test fixture and implements checks
// for InvoiceExpiryWatcher tests.
type invoiceExpiryWatcherTest struct {
	t                *testing.T
	watcher          *InvoiceExpiryWatcher
	testData         invoiceExpiryTestData
	canceledInvoices []lntypes.Hash
}

// newInvoiceExpiryWatcherTest creates a new InvoiceExpiryWatcher test fixture
// and sets up the test environment.
func newInvoiceExpiryWatcherTest(t *testing.T, now time.Time,
	numExpiredInvoices, numPendingInvoices int) *invoiceExpiryWatcherTest {

	test := &invoiceExpiryWatcherTest{
		watcher: NewInvoiceExpiryWatcher(clock.NewTestClock(testTime)),
		testData: generateInvoiceExpiryTestData(
			t, now, 0, numExpiredInvoices, numPendingInvoices,
		),
	}

	err := test.watcher.Start(func(paymentHash lntypes.Hash) error {
		test.canceledInvoices = append(test.canceledInvoices, paymentHash)
		return nil
	})

	if err != nil {
		t.Fatalf("cannot start InvoiceExpiryWatcher: %v", err)
	}

	return test
}

func (t *invoiceExpiryWatcherTest) checkExpectations() {
	// Check that invoices that got canceled during the test are the ones
	// that expired.
	if len(t.canceledInvoices) != len(t.testData.expiredInvoices) {
		t.t.Fatalf("expected %v cancellations, got %v",
			len(t.testData.expiredInvoices), len(t.canceledInvoices))
	}

	for i := range t.canceledInvoices {
		if _, ok := t.testData.expiredInvoices[t.canceledInvoices[i]]; !ok {
			t.t.Fatalf("wrong invoice canceled")
		}
	}
}

// Tests that InvoiceExpiryWatcher can be started and stopped.
func TestInvoiceExpiryWatcherStartStop(t *testing.T) {
	watcher := NewInvoiceExpiryWatcher(clock.NewTestClock(testTime))
	cancel := func(lntypes.Hash) error {
		t.Fatalf("unexpected call")
		return nil
	}

	if err := watcher.Start(cancel); err != nil {
		t.Fatalf("unexpected error upon start: %v", err)
	}

	if err := watcher.Start(cancel); err == nil {
		t.Fatalf("expected error upon second start")
	}

	watcher.Stop()

	if err := watcher.Start(cancel); err != nil {
		t.Fatalf("unexpected error upon start: %v", err)
	}
}

// Tests that no invoices will expire from an empty InvoiceExpiryWatcher.
func TestInvoiceExpiryWithNoInvoices(t *testing.T) {
	t.Parallel()
	test := newInvoiceExpiryWatcherTest(t, testTime, 0, 0)

	time.Sleep(testTimeout)
	test.watcher.Stop()
	test.checkExpectations()
}

// Tests that if all add invoices are expired, then all invoices
// will be canceled.
func TestInvoiceExpiryWithOnlyExpiredInvoices(t *testing.T) {
	t.Parallel()

	test := newInvoiceExpiryWatcherTest(t, testTime, 0, 5)

	for paymentHash, invoice := range test.testData.pendingInvoices {
		test.watcher.AddInvoice(paymentHash, invoice)
	}

	time.Sleep(testTimeout)
	test.watcher.Stop()
	test.checkExpectations()
}

// Tests that if some invoices are expired, then those invoices
// will be canceled.
func TestInvoiceExpiryWithPendingAndExpiredInvoices(t *testing.T) {
	t.Parallel()
	test := newInvoiceExpiryWatcherTest(t, testTime, 5, 5)

	for paymentHash, invoice := range test.testData.expiredInvoices {
		test.watcher.AddInvoice(paymentHash, invoice)
	}

	for paymentHash, invoice := range test.testData.pendingInvoices {
		test.watcher.AddInvoice(paymentHash, invoice)
	}

	time.Sleep(testTimeout)
	test.watcher.Stop()
	test.checkExpectations()
}

// Tests adding multiple invoices at once.
func TestInvoiceExpiryWhenAddingMultipleInvoices(t *testing.T) {
	t.Parallel()
	test := newInvoiceExpiryWatcherTest(t, testTime, 5, 5)
	var invoices []channeldb.InvoiceWithPaymentHash
	for hash, invoice := range test.testData.expiredInvoices {
		invoices = append(invoices,
			channeldb.InvoiceWithPaymentHash{
				Invoice:     *invoice,
				PaymentHash: hash,
			},
		)
	}
	for hash, invoice := range test.testData.pendingInvoices {
		invoices = append(invoices,
			channeldb.InvoiceWithPaymentHash{
				Invoice:     *invoice,
				PaymentHash: hash,
			},
		)
	}

	test.watcher.AddInvoices(invoices)
	time.Sleep(testTimeout)
	test.watcher.Stop()
	test.checkExpectations()
}
