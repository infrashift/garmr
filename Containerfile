# Build stage
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /src

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build
ARG VERSION=dev
RUN make build-linux VERSION=${VERSION}

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 garmr && \
    adduser -u 1000 -G garmr -s /bin/sh -D garmr

# Create directories
RUN mkdir -p /etc/garmr/policies /etc/garmr/data /var/lib/garmr && \
    chown -R garmr:garmr /etc/garmr /var/lib/garmr

# Copy binaries
COPY --from=builder /src/bin/garmr-server-linux /usr/local/bin/garmr-server
COPY --from=builder /src/bin/garmr-linux /usr/local/bin/garmr

# Copy default config
COPY config.example.yaml /etc/garmr/config.yaml

USER garmr

EXPOSE 8080 9090

ENTRYPOINT ["/usr/local/bin/garmr-server"]
CMD ["--config", "/etc/garmr/config.yaml"]

# Health check (port 8080 = HTTP API, the active listener)
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD /usr/local/bin/garmr health --server localhost:8080 || exit 1
