//go:build windows

package platform

import "testing"

func TestAuditUsesETWInsteadOfBlockingHooks(t *testing.T) {
	p, err := New(Config{AuditMode: true})
	if err != nil {
		t.Fatal(err)
	}
	if !p.(*WindowsPlatform).cfg.SkipEBPF {
		t.Fatal("audit must not load kernel hooks that cannot be toggled to audit")
	}
}
