ARG GOBGP_VERSION=4.5.0
FROM alpine:3.20 AS fetch
ARG GOBGP_VERSION
RUN apk add --no-cache wget ca-certificates && \
    wget -O /tmp/gobgp.tar.gz \
      "https://github.com/osrg/gobgp/releases/download/v${GOBGP_VERSION}/gobgp_${GOBGP_VERSION}_linux_amd64.tar.gz" && \
    tar -xzf /tmp/gobgp.tar.gz -C /usr/local/bin gobgpd gobgp

FROM alpine:3.20
COPY --from=fetch /usr/local/bin/gobgpd /usr/local/bin/gobgpd
COPY --from=fetch /usr/local/bin/gobgp /usr/local/bin/gobgp
EXPOSE 50051 179
ENTRYPOINT ["gobgpd"]
