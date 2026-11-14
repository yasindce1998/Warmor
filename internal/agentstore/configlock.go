package agentstore

// WithConfigurationLock serializes administrator trust changes with signed
// verification/publication. All writers must acquire this same stable lock file
// exclusively BEFORE atomically replacing configuration, and never unlink it.
// Lock contention fails closed instead of blocking activation indefinitely.
func WithConfigurationLock(path string, fn func() error) error {
	f, err := lockFile(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return fn()
}
