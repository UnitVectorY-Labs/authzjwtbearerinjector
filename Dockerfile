# Use the official Golang image for building the application
FROM golang:1.23 as builder

# Set the working directory inside the container
WORKDIR /app

# Copy the Go modules manifest and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the Go gRPC server
RUN go build -o server .

# Use a minimal base image for running the compiled binary
FROM gcr.io/distroless/base-debian12

# Copy the built server binary into the runtime container
COPY --from=builder /app/server /server

# Expose the port that the gRPC server will listen on
EXPOSE 50051

# Run the gRPC server binary
CMD ["/server"]