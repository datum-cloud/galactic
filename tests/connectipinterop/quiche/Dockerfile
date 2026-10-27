# google/quiche's masque_client at a pinned commit, built twice: as released,
# and with its CONNECT-IP packet sizing corrected. The encapsulated QUIC client
# sizes its packets to the outer datagram payload, then prepends a 40-byte IPv6
# and an 8-byte UDP header in CONNECT-IP mode, so no packet fits until those 48
# bytes are subtracted. See docs/edge/connectip-interop.md.
FROM debian:trixie AS build
ARG QUICHE_COMMIT=c607d240fb0125f41f4e8e6206a847d6bd1dbe3c
ARG BAZELISK_VERSION=v1.25.0
ARG BAZELISK_SHA256=fd8fdff418a1758887520fa42da7e6ae39aefc788cf5e7f7bb8db6934d279fc4
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends git libicu-dev clang curl ca-certificates python3 >/dev/null
RUN curl -fsSL -o /usr/local/bin/bazel \
      https://github.com/bazelbuild/bazelisk/releases/download/${BAZELISK_VERSION}/bazelisk-linux-amd64 \
 && echo "${BAZELISK_SHA256}  /usr/local/bin/bazel" | sha256sum -c - \
 && chmod +x /usr/local/bin/bazel
WORKDIR /src/quiche
RUN git init -q . \
 && git fetch -q --depth 1 https://github.com/google/quiche.git ${QUICHE_COMMIT} \
 && git checkout -q FETCH_HEAD
ENV CC=clang CXX=clang++
RUN bazel build -c opt //quiche:masque_client && cp bazel-bin/quiche/masque_client /masque_client
RUN sed -i 's|/\* context ID set to zero \*/ sizeof(uint8_t);|/* context ID set to zero */ sizeof(uint8_t) - /* IPv6 + UDP headers */ 48;|' \
      quiche/quic/masque/masque_encapsulated_client.cc \
 && grep -q 'IPv6 + UDP headers' quiche/quic/masque/masque_encapsulated_client.cc \
 && bazel build -c opt //quiche:masque_client && cp bazel-bin/quiche/masque_client /masque_client_patched

FROM debian:trixie-slim
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends libicu76 ca-certificates >/dev/null \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /masque_client /masque_client_patched /usr/local/bin/
