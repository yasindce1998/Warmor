# Build the daemon (Go).
# Pinned multi-platform index digests; update deliberately with security scans.
FROM golang:1.26.11@sha256:957952ae74dc010608717144399a59a2c6e82ea03d63be1c7ff6577c5a135f93 AS builder
ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH
ENV GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=readonly -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X github.com/yasindce1998/warmor/internal/version.Version=${VERSION}" -o /warmor-daemon ./cmd/warmor-daemon \
 && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=readonly -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /warmor-compile ./cmd/warmor-compile \
 && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=readonly -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X github.com/yasindce1998/warmor/internal/version.Version=${VERSION}" -o /warmor-controller ./cmd/warmor-controller

# Compile the default policy YAML to WASM. warmor-compile generates Rust and
# runs cargo, so this stage needs the Rust toolchain and the wasm32 target.
# The distroless runtime image has neither, which is why the policy must be
# compiled here rather than on the node.
FROM rust:1.100.0-slim@sha256:e9d95b74296f7126a83ae3d041aeaba1ff4c478f13abc5cc034fcf7c131c3d4a AS rust-base
# The current immutable Rust base predates these Debian security fixes. Keep
# the compiler/Cargo runtime intact and upgrade only the affected packages to
# exact versions, using Debian's signed package indexes/checksums. Missing pins
# fail the build; never fall back to the vulnerable versions or skip scanning.
RUN apt-get update \
 && apt-get install -y --no-install-recommends --only-upgrade --no-remove \
      linux-libc-dev=6.12.117-1 \
      zlib1g=1:1.3.dfsg+really1.3.1-1+deb13u1 \
 && test "$(dpkg-query -W -f='${Version}' linux-libc-dev)" = '6.12.117-1' \
 && test "$(dpkg-query -W -f='${Version}' zlib1g)" = '1:1.3.dfsg+really1.3.1-1+deb13u1' \
 && rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32-unknown-unknown
ENV CARGO_NET_OFFLINE=true

FROM rust-base AS policy
WORKDIR /src
COPY --from=builder /warmor-compile /usr/local/bin/warmor-compile
COPY deploy/default-policy.yaml /src/default-policy.yaml
# warmor-compile shells out to cargo and writes next to the source; keep the
# build writable and pass the source as an argument.
RUN mkdir -p /work && cd /work \
 && cp /src/default-policy.yaml . \
 && warmor-compile -o /work/policy.wasm default-policy.yaml

# The WarmorPolicy controller. Unlike the agent image (distroless), this
# one needs the Rust toolchain at runtime: it compiles WarmorPolicy
# custom resources into WASM. The generated crates are dependency-free,
# so policy compiles are offline and take seconds, not minutes. It ships
# the same default policy the agent image bakes, so "no WarmorPolicy
# exists" syncs the cluster default rather than an empty policy.
# Build with: docker build --target controller -f deploy/Dockerfile .
FROM rust-base AS controller
COPY --from=builder /warmor-controller /warmor-controller
COPY --from=policy /work/policy.wasm /etc/warmor-controller/default-policy.wasm
EXPOSE 9090
ENTRYPOINT ["/warmor-controller"]

FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2 AS daemon
COPY --from=builder /warmor-daemon /warmor-daemon
COPY --from=policy /work/policy.wasm /etc/warmor/policy.wasm
EXPOSE 9090
ENTRYPOINT ["/warmor-daemon"]
