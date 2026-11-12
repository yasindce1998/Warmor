# Build the daemon (Go).
FROM golang:1.26 AS builder
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X github.com/yasindce1998/warmor/internal/version.Version=${VERSION}" -o /warmor-daemon ./cmd/warmor-daemon \
 && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /warmor-compile ./cmd/warmor-compile \
 && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X github.com/yasindce1998/warmor/internal/version.Version=${VERSION}" -o /warmor-controller ./cmd/warmor-controller

# Compile the default policy YAML to WASM. warmor-compile generates Rust and
# runs cargo, so this stage needs the Rust toolchain and the wasm32 target.
# The distroless runtime image has neither, which is why the policy must be
# compiled here rather than on the node.
FROM rust:1.82-slim AS policy
WORKDIR /src
COPY --from=builder /warmor-compile /usr/local/bin/warmor-compile
RUN rustup target add wasm32-unknown-unknown
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
FROM rust:1.82-slim AS controller
RUN rustup target add wasm32-unknown-unknown
COPY --from=builder /warmor-controller /warmor-controller
COPY --from=policy /work/policy.wasm /etc/warmor-controller/default-policy.wasm
EXPOSE 9090
ENTRYPOINT ["/warmor-controller"]

FROM gcr.io/distroless/static:latest
COPY --from=builder /warmor-daemon /warmor-daemon
COPY --from=policy /work/policy.wasm /etc/warmor/policy.wasm
EXPOSE 9090
ENTRYPOINT ["/warmor-daemon"]
