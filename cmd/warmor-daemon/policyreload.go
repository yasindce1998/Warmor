package main

import "errors"

var errFleetLocalReload = errors.New("local policy reload is disabled with --server: the fleet client exclusively owns activation and recovery; publish policy changes through the server")

// Signed deployment publication has a different durable commit owner/order.
// Do not compose it with the experimental live-first generation transaction
// until that integration is independently reviewed, including bootstrap/restart.
func checkGenerationAssignmentMode(signed, generations bool) error {
	if signed && generations {
		return errors.New("--signed-assignments cannot be combined with --experimental-atomic-generations until their activation integration is reviewed")
	}
	return nil
}

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
