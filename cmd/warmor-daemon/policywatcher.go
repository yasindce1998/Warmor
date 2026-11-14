package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const policyWatchInterval = 2 * time.Second

func policyContentIdentity(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return "", err
	}
	sig, err := os.ReadFile(resolved + ".sig")
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	return fmt.Sprintf("%x/%x", sha256.Sum256(data), sha256.Sum256(sig)), nil
}

// Hash content instead of increasing mtime, and acknowledge only a successful
// activation. Unchanged bytes are retried after failures. Capture the baseline
// synchronously so an immediate write cannot race goroutine initialization.
func watchPolicyActivation(path string, activate func() error, interval time.Duration) func() {
	active, _ := policyContentIdentity(path)
	var once sync.Once
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				desired, err := policyContentIdentity(path)
				if err != nil || desired == active {
					continue
				}
				if err := activate(); err != nil {
					log.Printf("Policy activation failed (will retry): %v", err)
					continue
				}
				if after, err := policyContentIdentity(path); err == nil && after == desired {
					active = desired
				}
			}
		}
	}()
	return func() { once.Do(func() { close(stop) }); <-done }
}

// Channel adapters provide notifications only. The daemon uses the direct
// activation callback above to receive real reload acknowledgement.
func startPolicyWatcher(path string, reloadCh chan<- struct{}) func() {
	return watchPolicyFile(path, reloadCh, policyWatchInterval)
}

func watchPolicyFile(path string, reloadCh chan<- struct{}, interval time.Duration) func() {
	return watchPolicyActivation(path, func() error {
		select {
		case reloadCh <- struct{}{}:
		default:
		}
		return nil
	}, interval)
}
