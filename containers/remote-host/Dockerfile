# A plain off-fabric host for deploy/containerlab's gvpc lab: nginx plus
# enough network tooling to configure a static transit link and to act as a
# client against an edge gateway's ingress VIP. Runs no Galactic component
# and speaks no BGP -- see gvpc.clab.yaml's remote-host node and
# node_files/tr4/frr.conf, which originates this host's subnets on its
# behalf.
#
# Pinned to a digest-free alpine tag deliberately: this image is built
# locally by `task build:remote-host` and never pushed anywhere, matching
# fabric-router:latest's own lab-only status.
FROM alpine:3.24

# iproute2: the startup script configures addresses and routes itself
# (containerlab assigns nothing on a p2p link, and the FRR-based nodes get
# theirs from zebra instead). curl/tcpdump/bind-tools are for driving and
# observing traffic from this end.
RUN apk add --no-cache \
      nginx \
      iproute2 \
      curl \
      tcpdump \
      bind-tools

# Serve something identifiable, so a curl from a tenant pod or another site
# proves it reached *this* host rather than any other nginx in the lab. The
# shipped default.conf is replaced outright, not added to: Alpine's version
# is a catch-all default_server that returns 404 for every request, which
# would shadow any site added alongside it.
RUN mkdir -p /var/www/localhost/htdocs \
    && printf 'remote-host: off-fabric nginx on tr4\n' \
       > /var/www/localhost/htdocs/index.html \
    && printf '%s\n' \
       'server {' \
       '    listen 80 default_server;' \
       '    listen [::]:80 default_server;' \
       '    root /var/www/localhost/htdocs;' \
       '    location / {' \
       '        try_files $uri $uri/ =404;' \
       '    }' \
       '}' \
       > /etc/nginx/http.d/default.conf

EXPOSE 80
