package main

import (
	"testing"

	"github.com/yasindce1998/warmor/internal/controller"
)

func TestReceiptListenerDisabledUnlessExplicitAndProvisioned(t *testing.T) {
	oldEnabled, oldCert, oldKey := *receiptsEnabled, *receiptsCert, *receiptsKey
	t.Cleanup(func() { *receiptsEnabled, *receiptsCert, *receiptsKey = oldEnabled, oldCert, oldKey })
	*receiptsEnabled = false
	if server, err := startReceipts(controller.New(nil, controller.Options{}), nil, func() {}); server != nil || err != nil {
		t.Fatalf("disabled receipts started: %v %v", server, err)
	}
	*receiptsEnabled = true
	*receiptsCert, *receiptsKey = "", ""
	if server, err := startReceipts(controller.New(nil, controller.Options{}), nil, func() {}); server != nil || err == nil {
		t.Fatal("receipt listener enabled without provisioned TLS")
	}
}
