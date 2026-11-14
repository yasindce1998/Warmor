package kernelmap

// MaxPolicyPathBytes is the shared exact-path fast-path limit. The binary
// WASM ABI has 128 primary-string bytes; reserve one byte so a truncated
// 128-byte input cannot equal an allowed static path. Linux sensors capture
// 256 bytes including NUL. Larger inputs stay out of dynamic kernel decisions
// and make static process allowlists ineligible.
const MaxPolicyPathBytes = 127
