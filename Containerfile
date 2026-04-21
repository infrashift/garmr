# syntax=docker/dockerfile:1.7
#
# Multi-stage, multi-arch build for Garmr.
# Works with both `docker build` and `docker buildx build --platform=...`.

FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG TARGETOS
ARG TARGETARCH

# Build statically for the target platform requested by buildx.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/garmr-server ./cmd/garmr-server && \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/garmr ./cmd/garmr

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

RUN addgroup -g 1000 garmr && \
    adduser -u 1000 -G garmr -s /bin/sh -D garmr

RUN mkdir -p /etc/garmr/policies /etc/garmr/data /var/lib/garmr /var/log/garmr && \
    chown -R garmr:garmr /etc/garmr /var/lib/garmr /var/log/garmr

COPY --from=builder /out/garmr-server /usr/local/bin/garmr-server
COPY --from=builder /out/garmr        /usr/local/bin/garmr
COPY config.example.yaml /etc/garmr/config.yaml

USER garmr

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/garmr-server"]
CMD ["--config", "/etc/garmr/config.yaml"]

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD /usr/local/bin/garmr health --server localhost:8080 || exit 1
