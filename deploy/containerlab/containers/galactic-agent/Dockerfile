FROM golang:1.26 AS builder
WORKDIR /src
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o bin/galactic-agent cmd/galactic-agent/main.go

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /src/bin/galactic-agent /usr/local/bin/galactic-agent
ENTRYPOINT ["/usr/local/bin/galactic-agent"]
