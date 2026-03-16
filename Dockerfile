FROM golang:1.26-alpine AS builder

WORKDIR /app

# Copy dependency manifests first to leverage layer caching.
# go mod download uses the pinned go.sum hashes — no re-resolution at build time.
COPY go.mod go.sum ./
RUN go mod download -x

# Copy source and build a static, stripped binary.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /app/gorev .

FROM alpine:3.21

# Non-root user for least-privilege execution
RUN adduser -D -u 1001 gorev

# Create the data directory with least-privilege permissions.
# The gorev user owns it; no other OS users should read PKI material.
RUN mkdir -p /data/cas /data/crls /data/responders \
    && chown -R gorev:gorev /data \
    && chmod -R 750 /data

USER gorev
WORKDIR /home/gorev
COPY --from=builder /app/gorev .

EXPOSE 8080
CMD ["./gorev"]
