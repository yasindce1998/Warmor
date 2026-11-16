package main

import (
	"strings"
	"testing"
)

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

func TestControllerReceiptsRejectFleetBeforeTrustOrCapture(t *testing.T) {
	for _, flags := range [][]string{
		{"--signed-assignments", "--assignment-config=/missing/trust", "--assignment-clock-health=/missing/clock", "--assignment-state-dir=/missing/state"},
		{"--server=https://fleet.invalid"},
		{"--signed-assignments", "--server=https://fleet.invalid"},
	} {
		args := append([]string{"--receipt-controller=https://controller.invalid", "--receipt-ca=/missing/ca", "--policy=/missing/policy"}, flags...)
		r := runChild(t, nil, args...)
		if r.code == 0 || !strings.Contains(r.stderr, "controller node receipts cannot be combined") {
			t.Fatalf("unsupported cross-mode reached startup/trust/capture: %+v", r)
		}
		for _, forbidden := range []string{"warmor_starting", "must be run with elevated", "configuration/state", "read receipt", "Failed to create enforcer"} {
			if strings.Contains(r.stderr, forbidden) {
				t.Fatalf("mode rejected too late: %s", r.stderr)
			}
		}
	}
}
