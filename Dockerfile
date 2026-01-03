# STAGE 1: Build the application
# UPDATED: Changed from 1.22 to 1.24 to match your go.mod requirement
FROM golang:1.24-bookworm AS builder

# Install Protocol Buffers Compiler
RUN apt-get update && apt-get install -y protobuf-compiler

# Set working directory
WORKDIR /app

# Copy dependency files
COPY go.mod go.sum ./
RUN go mod download

# Install Go plugins for Protoc
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
RUN go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@latest

# Add Go bin to PATH
ENV PATH="$PATH:$(go env GOPATH)/bin"

# Copy source code
COPY . .

# Generate the code from .proto
RUN protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    --grpc-gateway_out=. --grpc-gateway_opt=paths=source_relative \
    proto/whitelist.proto

# Build the binary
RUN go build -o main cmd/server/main.go

# STAGE 2: Run the application (Small image)
FROM debian:bookworm-slim

# Install necessary certificates for HTTPS
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /root/

# Copy the binary from the builder stage
COPY --from=builder /app/main .

# Command to run
CMD ["./main"]
