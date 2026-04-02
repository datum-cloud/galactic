FROM golang:1.24-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /bgp ./cmd/bgp

FROM alpine:3.19
RUN adduser -D -u 65532 nonroot
COPY --from=build /bgp /usr/local/bin/bgp
USER 65532:65532
ENTRYPOINT ["bgp"]
