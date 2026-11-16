// This module is a compile-time proof that an external implementation (for
// example warmor-saas) can consume the public control-plane contract without
// importing any of this repository's internal packages.
module github.com/yasindce1998/warmor/tests/controlplane-consumer

go 1.26.0

require github.com/yasindce1998/warmor v0.0.0

replace github.com/yasindce1998/warmor => ../..
