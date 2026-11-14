package main

import "errors"

var errFleetLocalReload = errors.New("local policy reload is disabled with --server: the fleet client exclusively owns activation and recovery; publish policy changes through the server")

// reloadLocalPolicy is the signal-path boundary. A fleet reload must never
// bypass OnUpdate's identity withdrawal and immutable pending-revision owner:
// even a failed reload may already have committed a new live generation.
// Reject before calling the enforcer, not by invalidating identity afterward.
func reloadLocalPolicy(fleetManaged bool, reload func() error) error {
	if fleetManaged {
		return errFleetLocalReload
	}
	return reload()
}
