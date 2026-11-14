# Dashboard access

The optional daemon dashboard exposes policy evaluations, including process
names and decision reasons. Treat this information as sensitive.

## Local use (default)

```sh
sudo warmor-daemon --policy policy.wasm --dashboard-port 8080
# Open http://127.0.0.1:8080/dashboard
```

Port `0` (the default) disables the dashboard. When enabled, the default bind
address is **127.0.0.1**, not all interfaces. `--dashboard-bind ::1` selects
IPv6 loopback. Bind values must be literal IP addresses or `localhost` (which
selects 127.0.0.1); empty hosts, hostnames, URLs and host:port values are rejected.

**Compatibility:** older versions listened on every interface. Deployments
that intentionally need remote access must now set `--dashboard-bind` explicitly.
Metrics listener settings are separate and unaffected by these dashboard flags.
For remote administration, prefer an SSH tunnel to the loopback listener:

```sh
ssh -N -L 8080:127.0.0.1:8080 user@node
```

Without authentication, any local process/user able to reach the listener can
read the dashboard. Loopback is a network exposure default, not user isolation.

## Optional authentication

Set either `WARMOR_DASHBOARD_TOKEN` in the daemon's environment **or**
`--dashboard-token-file /etc/warmor/dashboard.token`, never both. Keep the file
readable only by the daemon (for example mode 0600). File contents are a single
nonempty secret with an optional final LF/CRLF. Whitespace/control characters,
empty secrets, oversized files and unreadable files are startup errors rather
than silently disabling authentication. Restart the daemon to rotate the secret.
Use a high-entropy password (for example 32 random bytes encoded as hex).

```sh
sudo warmor-daemon --policy policy.wasm --dashboard-port 8080 \
  --dashboard-token-file /etc/warmor/dashboard.token
```

The browser prompts for HTTP Basic credentials: username **`warmor`**, password
the configured token. The same-origin native `EventSource` connection reuses
the browser's credentials for `/dashboard/events`, including reconnects; no
custom JavaScript Authorization header or token-bearing URL is needed. The
server compares password hashes in constant time and protects both the HTML
and SSE stream, including buffered history. Authentication is optional and
disabled if neither source is configured.

There is deliberately no command-line token-value flag, URL query token, or
JavaScript/local-storage secret. Do not put credentials into browser URLs,
query strings, logs or shell command arguments. The daemon logs the actual
listener address and authentication enabled/disabled state, not token values
or request URLs. Ensure any proxy also redacts Authorization headers and does
not log credentials. HTTP Basic is not encryption: **never send it over an
untrusted plaintext network**. Browsers may retain Basic credentials until
the browser session ends; there is no dashboard logout/session manager.

## Remote access and reverse proxies

Use a trusted HTTPS reverse proxy, preferably on the same host with the
dashboard left on loopback. Terminate TLS and authenticate users at the proxy
(SSO, mTLS, or Basic over HTTPS); restrict the backend with firewall/network
policy so clients cannot bypass the proxy. The dashboard does not interpret
forwarded identity headers. If daemon Basic auth is also enabled, forward the
matching Authorization header or configure it as a protected proxy secret.

Example Nginx location (inside an HTTPS server with certificates and its own
authentication already configured):

```nginx
location = /dashboard {
    proxy_pass http://127.0.0.1:8080;
}
location = /dashboard/events {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_buffering off;
    proxy_cache off;
    proxy_read_timeout 1h;
}
```

Preserve `/dashboard` and `/dashboard/events` at the origin root; the UI uses
the latter as a same-origin absolute path. Do not cache either endpoint. Idle
SSE streams may reconnect when a proxy's own read timeout expires.

If a separate proxy host/container must reach the backend, explicitly choose
a private interface with `--dashboard-bind 192.0.2.10` (replace with the node's
actual private IP). `--dashboard-bind 0.0.0.0` and `--dashboard-bind ::` are
explicit all-interface choices, **not recommended defaults**. The daemon logs
the bound address and warns for non-loopback listeners. Binding remotely does
not add TLS or automatically enable authentication; protect the backend
network and configure authentication intentionally. No live public listener
is needed to test these bind configurations.

## HTTP limits and streaming

The dedicated dashboard server uses a 5-second read-header timeout, 10-second
request-read timeout, 60-second idle keep-alive timeout and a 16 KiB header
limit. Its write timeout is deliberately zero: an active SSE response must
not expire on the metrics server's ordinary response deadline. Responses use
`Cache-Control: no-store`, `Referrer-Policy: no-referrer`, MIME sniffing
protection and frame denial; SSE also asks compatible proxies not to buffer.
No cross-origin read access is enabled. Event fields are rendered as text,
not executable HTML.
