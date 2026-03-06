FROM golang:1.24 AS builder
WORKDIR /workspace
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download
COPY api api
COPY srv6 srv6
COPY main.go main.go
RUN CGO_ENABLED=0 go build -a -o galactic-agent main.go

FROM gcr.io/distroless/static
WORKDIR /
COPY --from=builder /workspace/galactic-agent  .
ENTRYPOINT ["/galactic-agent"]
