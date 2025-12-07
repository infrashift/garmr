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
RUN addgroup -g 1000 q && \
    adduser -u 1000 -G q -s /bin/sh -D q

# Create directories
RUN mkdir -p /etc/q/policies /etc/q/data /var/lib/q && \
    chown -R q:q /etc/q /var/lib/q

# Copy binaries
COPY --from=builder /src/bin/q-server-linux /usr/local/bin/q-server
COPY --from=builder /src/bin/q-linux /usr/local/bin/q

# Copy default config
COPY config.example.yaml /etc/q/config.yaml

USER q

EXPOSE 8080 9090

ENTRYPOINT ["/usr/local/bin/q-server"]
CMD ["--config", "/etc/q/config.yaml"]

# Health check
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD /usr/local/bin/q health --server localhost:9090 --insecure || exit 1
