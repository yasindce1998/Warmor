package main

import "testing"

func TestNodeReceiptClientDisabledAndControllerTrustRequired(t *testing.T) {
	oldURL, oldCA := *receiptURL, *receiptCA
	t.Cleanup(func() { *receiptURL, *receiptCA = oldURL, oldCA })
	*receiptURL = ""
	if client, err := newNodeReceiptClient(nil); client != nil || err != nil {
		t.Fatalf("disabled client initialized: %v %v", client, err)
	}
	*receiptURL = "https://controller.test"
	*receiptCA = ""
	if client, err := newNodeReceiptClient(nil); client != nil || err == nil {
		t.Fatal("receipt client enabled without explicit controller trust")
	}
}
