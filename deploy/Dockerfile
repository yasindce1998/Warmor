FROM golang:1.26 AS builder
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X github.com/yasindce1998/warmor/internal/version.Version=${VERSION}" -o /warmor-daemon ./cmd/warmor-daemon

FROM gcr.io/distroless/static:latest
COPY --from=builder /warmor-daemon /warmor-daemon
EXPOSE 9090
ENTRYPOINT ["/warmor-daemon"]
