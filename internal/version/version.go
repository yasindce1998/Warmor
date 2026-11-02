package version

// Version is the warmor version reported by --version, startup logs and the
// warmor_policy_info metric. The default marks a build from source; release
// builds override it via
//
//	-ldflags="-X github.com/yasindce1998/warmor/internal/version.Version=<tag>"
var Version = "dev"
