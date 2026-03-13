FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy dependency files and source code
COPY go.mod go.sum* ./
COPY . .
RUN go mod tidy

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/rev-responder main.go

FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/rev-responder .

EXPOSE 8080
CMD ["./rev-responder"]
