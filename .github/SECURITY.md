# Security policy

Warmor is experimental security software; platform and enforcement limitations
are documented in `docs/STATUS.md` and `docs/RELEASE_SUPPORT.md`. A passing
release gate does not imply production enforcement certification.

Please report suspected vulnerabilities privately using GitHub's **Security →
Report a vulnerability** for this repository, if private vulnerability reporting
is enabled. If that option is unavailable, open an issue requesting a private
reporting channel **without exploit details, credentials, private policies or
other sensitive data**. Maintainers must arrange a private channel before you
send those details. No response-time or support guarantee is currently offered.

Include affected versions/platforms, impact, a minimal reproduction, relevant
non-sensitive logs and any mitigation. Do not test on systems you do not own or
have explicit permission to assess.

Only the latest release is a candidate for security fixes. Verify release
checksums and provenance as described in `docs/RELEASING.md`; do not rely on
mutable container tags as evidence of artifact identity.
