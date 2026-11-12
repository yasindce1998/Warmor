package main

import (
	"log"
	"os"
	"sync"
	"time"
)

// policyWatchInterval is how often the policy file's mtime is checked.
// Polling (rather than inotify/fsnotify) keeps this dependency-free and
// behaves identically on every platform.
const policyWatchInterval = 2 * time.Second

// startPolicyWatcher monitors the policy file for changes and sends on
// reloadCh when a modification is detected. Returns a stop function.
//
// On Unix this complements SIGHUP: nothing sends SIGHUP inside Kubernetes,
// where a ConfigMap update lands as a file swap that only a watcher sees.
// On Windows it has always been the only reload trigger.
func startPolicyWatcher(policyPath string, reloadCh chan<- struct{}) func() {
	return watchPolicyFile(policyPath, reloadCh, policyWatchInterval)
}

// watchPolicyFile is startPolicyWatcher with an explicit poll interval;
// tests pass a short one. The interval is a parameter, not shared state,
// so shortening it in tests cannot race a running watcher.
func watchPolicyFile(policyPath string, reloadCh chan<- struct{}, interval time.Duration) func() {
	var once sync.Once
	stopCh := make(chan struct{})

	go func() {
		var lastMod time.Time
		info, err := os.Stat(policyPath)
		if err == nil {
			lastMod = info.ModTime()
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				info, err := os.Stat(policyPath)
				if err != nil {
					continue
				}
				if info.ModTime().After(lastMod) {
					lastMod = info.ModTime()
					log.Println("Policy file changed on disk, triggering reload...")
					select {
					case reloadCh <- struct{}{}:
					default:
					}
				}
			}
		}
	}()

	return func() { once.Do(func() { close(stopCh) }) }
}
