# Fabric router image: the upstream FRR image used for the eBGP fabric/transit
# roles in deploy/containerlab, layered with common network debugging tools
# so issues can be triaged from inside the container without a separate
# toolbox image.
ARG FRR_VERSION=10.2.0
FROM quay.io/frrouting/frr:${FRR_VERSION}

RUN apt-get update && apt-get install -y --no-install-recommends \
      tcpdump \
      mtr-tiny \
      telnet \
      dnsutils \
      curl \
    && rm -rf /var/lib/apt/lists/*

# Static FRR config common to every fabric/transit role. Copied to a
# non-standard path (rather than /etc/frr directly) because /etc/frr is an
# emptyDir in the fabric DaemonSets, populated at pod start by the frr-init
# container so frr.conf can still be swapped in per site; the daemonset's
# init command seeds it from here before layering the site-specific config
# in on top.
COPY containers/fabric-router/daemons containers/fabric-router/vtysh.conf /etc/frr-defaults/
