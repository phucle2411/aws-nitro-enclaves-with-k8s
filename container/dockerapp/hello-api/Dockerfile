FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod .
COPY go.sum .
COPY main.go .

# Install dependencies (if needed)
RUN go mod download

# Build a statically linked binary (for Alpine compatibility)
RUN CGO_ENABLED=0 GOOS=linux go build -o hello-api

# Final minimal Alpine image
FROM alpine:3.19
WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/hello-api .

# Run as non-root user (security best practice)
RUN adduser -D appuser && chown -R appuser:appuser /app
USER appuser

CMD ["/app/hello-api"]