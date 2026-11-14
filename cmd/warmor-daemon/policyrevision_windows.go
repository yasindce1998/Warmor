package main

import "errors"

// Do not substitute a pair of file renames or ignore a failed directory sync:
// neither preserves the immutable-pair publication/durability contract.
var errPolicyRevisionUnsupported = errors.New("durable fleet policy activation is unsupported on Windows: atomic revision links and directory durability barriers are not implemented; use a local signed --policy without --server")

func checkPolicyRevisionSupport() error { return errPolicyRevisionUnsupported }
