#!/usr/bin/env bash
# tailnet-feasibility.sh — Check that a Headscale tailnet runtime can serve a
# VPC through a host-owned attachment, end to end, on one Linux host.
#
# The topology lives entirely in network namespaces and containers named gtn-*:
#
#   gtn-node       the node namespace: canonical host VRFs vrf-a and vrf-b
#   gtn-wl-a/-b    one workload per VPC, both at the same address
#   gtn-bind-a/-b  one tailnet binding per VPC: tailscaled in kernel TUN mode,
#                  its own state, socket and node key, attached to its VPC by a
#                  pod VRF (vrf-tn) and a veth into the host VRF, with
#                  tailscale0 a persistent TUN enslaved to the pod VRF
#   gtn-site-a/-b  one remote subnet router per tailnet, both serving the
#                  same site prefix, with a host behind each (gtn-shost-a/-b)
#   gtn-mgmt       the management bridge every runtime's control and WireGuard
#                  traffic uses; the VPC VRFs never carry it
#   gtn-hs-a/-b    one Headscale per tailnet, with its embedded DERP server
#
# Each check prints PASS, FAIL, NOTE (a behavior recorded, not judged) or
# BLOCKED with the evidence it rests on.
#
# Usage, as root:
#   tailnet-feasibility.sh           build, check, clean up
#   tailnet-feasibility.sh --keep    leave the topology up after the checks
#   tailnet-feasibility.sh --down    only remove a kept topology
#
# Files. /run/gtn-tailnet is the state directory: it holds the run lock, the
# record of what this run created, the tailscaled sockets and pid files. The
# work directory, GTN_WORKDIR (default /run/gtn-tailnet/work), holds the
# tailscaled binaries copied from the image, the generated keys and helper
# scripts, the runtime state and the logs. The script runs files from it, so
# it refuses a work or state directory that is a symlink, is not owned by
# root with mode 0700, or sits in a directory other users can rename it in.
# It creates either one, with mode 0700, if it does not exist.
#
# Safety. One run at a time: the script holds an flock on
# /run/gtn-tailnet/lock and refuses to start while another run holds it. It
# records every namespace and container it creates, and cleanup (on exit, at
# the start of the next run, or with --down) removes only what is recorded:
# it stops the processes in those namespaces and the ones whose pid files
# still name our tailscaled or helper server, deletes the recorded
# namespaces and containers, and removes the work directory if it created it
# (otherwise only the entries it put there). It refuses to reuse a gtn-*
# namespace or container it did not record. tailscaled runs in the host
# mount namespace, so the script fingerprints /etc/resolv.conf and
# /var/lib/tailscale before the run and fails it if either changed.
#
# What stays behind: the pulled images in the Docker cache, the vrf and tun
# kernel modules it loads, and the empty lock file in /run/gtn-tailnet.
#
# Requires docker, iproute2, nftables, tcpdump, python3, jq, nsenter and
# flock, and the vrf and tun kernel modules.
set -euo pipefail

HEADSCALE_IMAGE=docker.io/headscale/headscale:v0.29.5@sha256:780ed2f9e85719a2211277433f2c8afb45105d0d25031949a6848a485f9e216d
TAILSCALE_IMAGE=docker.io/tailscale/tailscale:v1.104.1@sha256:87c55d6be56ad85b3d8bceca5f87f73de288c609131460dd1be1874c250cc41d
OPENSSL_IMAGE=docker.io/alpine/openssl:3.5.8@sha256:3f25da71f70eba788067daac3f3df03bd1de7a7c52ed89fa93b94ad2c92d986b

# The state directory: lock, record, sockets and pid files, kept short for
# the unix socket path limit.
RUN=/run/gtn-tailnet
LOCK=$RUN/lock
# RECORD lists what this run created, one "<kind> <name>" per line: ns,
# container, work-created or work-existing.
RECORD=$RUN/created
WORK=${GTN_WORKDIR:-$RUN/work}
BIN=$WORK/bin
# The entries the script creates in the work directory.
WORK_ENTRIES=(bin pki state log hs-a hs-b server.py client.py)
GUARD_FILES=(/etc/resolv.conf /var/lib/tailscale)

# Address plan. The management network is dual-stack: with no IPv4 at all,
# tailscaled's netcheck never sends an IPv4 STUN probe, reports IPv4 as unable
# to send, and magicsock rebinds and resets every peer's path on each endpoint
# update (check 5b shows it on an IPv6-only node).
MGMT_NET=fd99::
MGMT_NET4=10.99.0.
MGMT_GW=${MGMT_NET}fe
MGMT_GW4=${MGMT_NET4}254
VPC_PREFIX=fd00:10::/64
WORKLOAD=fd00:10::10
ATTACH_ADDR=fd00:10::100
SITE_PREFIX=fd00:5::/64
SITE_GW=fd00:5::1
SITE_HOST=fd00:5::10
POD_TABLE=100
UNREACHABLE_METRIC=4278198272
APP_PORT=8080

declare -A MGMT_ADDR=(
  [hs-a]=${MGMT_NET}1 [hs-b]=${MGMT_NET}2
  [bind-a]=${MGMT_NET}11 [bind-b]=${MGMT_NET}12 [bind-a2]=${MGMT_NET}13
  [site-a]=${MGMT_NET}21 [site-b]=${MGMT_NET}22 [probe]=${MGMT_NET}31
)
declare -A MGMT_ADDR4=(
  [hs-a]=${MGMT_NET4}1 [hs-b]=${MGMT_NET4}2
  [bind-a]=${MGMT_NET4}11 [bind-b]=${MGMT_NET4}12 [bind-a2]=${MGMT_NET4}13
  [site-a]=${MGMT_NET4}21 [site-b]=${MGMT_NET4}22
)
declare -A HOST_TABLE=([a]=10 [b]=11)

keep=false
case "${1:-}" in
  --keep) keep=true ;;
  --down) mode=down ;;
  "") ;;
  -h | --help)
    sed -n '/^# tailnet-feasibility.sh/,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  *)
    echo "unknown argument: $1" >&2
    exit 2
    ;;
esac

declare -a RESULTS=()

say() { printf '%s\n' "$*"; }
step() { printf '\n=== %s\n' "$*"; }
# show prints a command, runs it and prints its output, indented.
show() {
  printf '  $ %s\n' "$*"
  "$@" 2>&1 | sed 's/^/    /' || true
}
result() {
  local status=$1 id=$2
  shift 2
  RESULTS+=("$(printf '%-7s %-4s %s' "$status" "$id" "$*")")
  printf '\n>>> %s %s: %s\n' "$status" "$id" "$*"
}

nsx() {
  local ns=$1
  shift
  ip netns exec "gtn-$ns" "$@"
}
ts() {
  local name=$1
  shift
  ip netns exec "gtn-$name" "$BIN/tailscale" --socket="$RUN/$name.sock" "$@"
}
hs() {
  local inst=$1
  shift
  docker exec -e NO_COLOR=1 "gtn-hs-$inst" /ko-app/headscale "$@"
}

# wait_for retries a command once a second until it succeeds or the timeout
# (seconds) passes.
wait_for() {
  local timeout=$1
  shift
  local i
  for ((i = 0; i < timeout; i++)); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

link_mac() { ip -n "gtn-$1" -j link show "$2" | jq -r '.[0].address'; }
link_counter() { ip -n "gtn-$1" -j -s link show "$2" | jq -r ".[0].stats64.$3.packets"; }

# ---------------------------------------------------------------- teardown

die() {
  printf '%s\n' "$*" >&2
  exit 1
}

# record notes that this run created resource $2 of kind $1.
record() { printf '%s %s\n' "$1" "$2" >>"$RECORD"; }
unrecord() {
  [[ -f $RECORD ]] || return 0
  grep -vxF -- "$1 $2" "$RECORD" >"$RECORD.new" || true
  mv -f "$RECORD.new" "$RECORD"
}
# recorded prints the names recorded with kind $1.
recorded() {
  [[ -f $RECORD ]] || return 0
  awk -v k="$1" '$1 == k {print $2}' "$RECORD"
}

# ours succeeds when pid $1 is still a process this script started from work
# directory $2: tailscaled from its bin directory, the helper server, or the
# ip netns exec or env that execs into one of them.
ours() {
  local pid=$1 work=$2 a
  local -a argv=()
  [[ $pid =~ ^[0-9]+$ ]] || return 1
  { mapfile -d '' -t argv <"/proc/$pid/cmdline"; } 2>/dev/null || return 1
  ((${#argv[@]})) || return 1
  case ${argv[0]} in
    "$work/bin/tailscaled") return 0 ;;
    python3) [[ ${argv[1]:-} == "$work/server.py" ]] ;;
    ip | env)
      if [[ ${argv[0]} == ip ]]; then
        [[ ${argv[1]:-} == netns && ${argv[2]:-} == exec ]] || return 1
        recorded ns | grep -qxF -- "${argv[3]:-}" || return 1
      fi
      for a in "${argv[@]}"; do
        [[ $a == "$work/bin/tailscaled" || $a == "$work/server.py" ]] && return 0
      done
      return 1
      ;;
    *) return 1 ;;
  esac
}

# stop_ours sends signal $1 to every process this script started: the pids in
# its pid files that ours still recognizes, and every process left in a
# namespace it recorded.
stop_ours() {
  local sig=$1 work=$2 f pid ns
  for f in "$RUN"/*.pid; do
    [[ -e $f ]] || continue
    pid=$(<"$f")
    if [[ -n $work ]] && ours "$pid" "$work"; then
      kill "-$sig" "$pid" 2>/dev/null
    fi
  done
  for ns in $(recorded ns); do
    for pid in $(ip netns pids "$ns" 2>/dev/null); do
      kill "-$sig" "$pid" 2>/dev/null
    done
  done
}

# cleanup removes what the record lists, and nothing else. It runs in a
# subshell with errexit off, so one failed step does not skip the rest.
cleanup() (
  set +e
  local work created=false c ns e
  work=$(recorded work-created | head -1)
  if [[ -n $work ]]; then
    created=true
  else
    work=$(recorded work-existing | head -1)
  fi
  stop_ours TERM "$work"
  sleep 1
  stop_ours KILL "$work"
  rm -f "$RUN"/*.pid "$RUN"/*.sock
  for c in $(recorded container); do
    docker rm -f "$c" >/dev/null 2>&1
  done
  for ns in $(recorded ns); do
    if ip netns list | awk '{print $1}' | grep -qxF -- "$ns"; then
      ip netns del "$ns" || echo "warning: could not delete namespace $ns" >&2
    fi
  done
  if [[ -n $work ]]; then
    if $created; then
      rm -rf -- "$work"
    else
      for e in "${WORK_ENTRIES[@]}"; do
        rm -rf -- "${work:?}/$e"
      done
    fi
  fi
  rm -f "$RECORD" "$RECORD.new"
  return 0
)

# ---------------------------------------------------------------- safety

# dir_ok succeeds when $1 is a directory, not a symlink, owned by root with
# mode 0700.
dir_ok() {
  [[ ! -L $1 && -d $1 ]] || return 1
  [[ $(stat -c '%u %a' "$1") == "0 700" ]]
}

# parent_ok succeeds when no other user can rename or replace $1: its parent
# is a real path, with no symlinks, owned by root, and either not writable by
# group and others or sticky.
parent_ok() {
  local parent owner perm
  parent=$(dirname "$1")
  [[ $(realpath -e "$parent" 2>/dev/null) == "$parent" ]] || return 1
  read -r owner perm < <(stat -c '%u %a' "$parent")
  [[ $owner == 0 ]] || return 1
  (((8#$perm & 8#022) == 0 || (8#$perm & 8#1000) != 0))
}

# check_dir refuses a path the script must not use as a private directory.
check_dir() {
  local d=$1
  if [[ ! $d =~ ^/[A-Za-z0-9._/-]+$ || $d == */ || $d == *//* || $d == */./* ||
    $d == */../* || $d == */. || $d == */.. ]]; then
    die "refusing $d: not a plain absolute path"
  fi
  parent_ok "$d" ||
    die "refusing $d: its parent is a symlink, not owned by root, or writable by other users without the sticky bit"
  if [[ -e $d || -L $d ]]; then
    dir_ok "$d" || die "refusing $d: it exists but is not a directory owned by root with mode 0700"
  fi
}

# make_dir creates $1 with mode 0700. mkdir fails if another process created
# it first, and the result is checked again.
make_dir() {
  mkdir -m 700 "$1" && dir_ok "$1"
}

# setup_state creates the state directory and takes the run lock.
setup_state() {
  check_dir "$RUN"
  if [[ ! -d $RUN ]]; then
    make_dir "$RUN" || die "could not create $RUN"
  fi
  exec 9>>"$LOCK"
  flock -n 9 || die "another run holds $LOCK"
}

# setup_work creates the work directory, or adopts an existing one that
# passed check_dir and is empty, and records which. An adopted directory must
# be empty because cleanup removes the harness's entries from it by name.
setup_work() {
  check_dir "$WORK"
  if [[ -d $WORK ]]; then
    [[ -z $(ls -A -- "$WORK") ]] || die "$WORK exists and is not empty; pass an empty directory or none"
    record work-existing "$WORK"
  else
    make_dir "$WORK" || die "could not create $WORK"
    record work-created "$WORK"
  fi
}

# fingerprint prints the state of the host files tailscaled could reach
# through the shared mount namespace.
fingerprint() {
  local f
  for f in "${GUARD_FILES[@]}"; do
    if [[ -L $f ]]; then
      printf '%s symlink %s\n' "$f" "$(readlink "$f")"
    fi
    if [[ -d $f ]]; then
      printf '%s dir %s\n' "$f" "$(find "$f" -printf '%P %y %m %u %s %T@\n' | sort | sha256sum | cut -c1-64)"
    elif [[ -e $f ]]; then
      printf '%s file %s\n' "$f" "$(sha256sum <"$f" | cut -c1-64)"
    else
      printf '%s absent\n' "$f"
    fi
  done
}

GUARD_BEFORE=""
# guard_changed succeeds, and prints the difference, when a guarded host file
# changed since the baseline.
guard_changed() {
  local now
  [[ -n $GUARD_BEFORE ]] || return 1
  now=$(fingerprint)
  [[ $now != "$GUARD_BEFORE" ]] || return 1
  diff <(printf '%s\n' "$GUARD_BEFORE") <(printf '%s\n' "$now") | sed 's/^/  /'
  return 0
}

on_exit() {
  local rc=$?
  cleanup
  if guard_changed; then
    echo "FAIL: host files changed during the run (see above)" >&2
    exit 1
  fi
  if [[ -n $GUARD_BEFORE ]]; then
    say "host files unchanged after cleanup: ${GUARD_FILES[*]}"
  fi
  exit "$rc"
}

# ---------------------------------------------------------------- setup

preflight() {
  local missing=()
  local t
  [[ $(id -u) == 0 ]] || die "run as root"
  for t in docker ip nft tcpdump python3 jq nsenter flock stat realpath sha256sum; do
    command -v "$t" >/dev/null || missing+=("$t")
  done
  if ((${#missing[@]})); then
    die "missing tools: ${missing[*]}"
  fi
}

fetch() {
  local img c
  for img in "$HEADSCALE_IMAGE" "$TAILSCALE_IMAGE" "$OPENSSL_IMAGE"; do
    docker pull -q "$img" >/dev/null
  done
  mkdir -p "$BIN"
  c=gtn-fetch-$$
  docker create --name "$c" "$TAILSCALE_IMAGE" >/dev/null ||
    die "could not create container $c"
  record container "$c"
  docker cp -q "$c:/usr/local/bin/tailscaled" "$BIN/tailscaled"
  docker cp -q "$c:/usr/local/bin/tailscale" "$BIN/tailscale"
  docker rm "$c" >/dev/null
  unrecord container "$c"
  say "headscale: $HEADSCALE_IMAGE"
  say "  $(docker run --rm "$HEADSCALE_IMAGE" version 2>&1 | head -1)"
  say "tailscale: $TAILSCALE_IMAGE"
  say "  $("$BIN/tailscaled" --version | head -1), sha256 $(sha256sum "$BIN/tailscaled" | cut -c1-64)"
  say "kernel:    $(uname -r)"
}

# pki issues one self-signed certificate per Headscale, for its name and
# management addresses. The bundle of both is the clients' trust store.
pki() {
  local inst
  mkdir -p "$WORK/pki"
  for inst in a b; do
    docker run --rm -v "$WORK/pki:/pki" -w /pki "$OPENSSL_IMAGE" req -x509 \
      -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
      -subj "/CN=gtn-hs-$inst" \
      -addext "subjectAltName=DNS:hs-$inst.gtn.test,IP:${MGMT_ADDR[hs-$inst]},IP:${MGMT_ADDR4[hs-$inst]}" \
      -keyout "hs-$inst.key" -out "hs-$inst.crt" 2>/dev/null
  done
  cat "$WORK/pki/hs-a.crt" "$WORK/pki/hs-b.crt" >"$WORK/pki/bundle.pem"
}

# mgmt_attach connects namespace gtn-$1 to the management bridge as mgmt0,
# with the main table's default routes through it. tailscaled takes its
# default interface from the main table's IPv4 default route; without one it
# falls back to the first default route in any table, which in a binding
# namespace is the pod VRF's route out of the attachment.
mgmt_attach() {
  local name=$1
  ip -n gtn-mgmt link add "m-$name" type veth peer name mgmt0 netns "gtn-$name"
  ip -n gtn-mgmt link set "m-$name" master br0 up
  ip -n "gtn-$name" addr add "${MGMT_ADDR[$name]}/64" dev mgmt0 nodad
  ip -n "gtn-$name" link set mgmt0 up
  ip -n "gtn-$name" -6 route add default via "$MGMT_GW" dev mgmt0
  if [[ -n ${MGMT_ADDR4[$name]:-} ]]; then
    ip -n "gtn-$name" addr add "${MGMT_ADDR4[$name]}/24" dev mgmt0
    ip -n "gtn-$name" -4 route add default via "$MGMT_GW4" dev mgmt0
  fi
}

new_ns() {
  ip netns add "gtn-$1" ||
    die "namespace gtn-$1 already exists and this run did not create it; remove it first"
  record ns "gtn-$1"
  ip -n "gtn-$1" link set lo up
}

forwarding() {
  nsx "$1" sysctl -qw net.ipv6.conf.all.forwarding=1
}

headscale_up() {
  local inst=$1 dir=$WORK/hs-$1 addr=${MGMT_ADDR[hs-$1]} addr4=${MGMT_ADDR4[hs-$1]} pid
  mkdir -p "$dir/etc" "$dir/lib" "$dir/run"
  cp "$WORK/pki/hs-$inst.crt" "$dir/etc/tls.crt"
  cp "$WORK/pki/hs-$inst.key" "$dir/etc/tls.key"
  cat >"$dir/etc/config.yaml" <<EOF
# The embedded DERP region takes its host name from server_url, and clients
# build the DERP URL from it unbracketed, so it must be a name. Clients dial
# the ipv4/ipv6 addresses below and never resolve it; they reach the control
# server by address.
server_url: https://hs-$inst.gtn.test:443
listen_addr: "[::]:443"
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
noise:
  private_key_path: /var/lib/headscale/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: true
    region_id: 999
    region_code: gtn-$inst
    region_name: gtn-$inst embedded DERP
    verify_clients: true
    stun_listen_addr: "[::]:3478"
    private_key_path: /var/lib/headscale/derp_server_private.key
    automatically_add_embedded_derp_region: true
    ipv4: $addr4
    ipv6: $addr
  urls: []
  paths: []
  auto_update_enabled: false
disable_check_updates: true
database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite
tls_cert_path: /etc/headscale/tls.crt
tls_key_path: /etc/headscale/tls.key
log:
  level: info
dns:
  magic_dns: false
  override_local_dns: false
  base_domain: tailnet-$inst.test
  nameservers:
    global: []
unix_socket: /var/run/headscale/headscale.sock
unix_socket_permission: "0770"
EOF
  docker create --name "gtn-hs-$inst" --network none \
    -v "$dir/etc:/etc/headscale:ro" -v "$dir/lib:/var/lib/headscale" -v "$dir/run:/var/run/headscale" \
    "$HEADSCALE_IMAGE" serve >/dev/null ||
    die "container gtn-hs-$inst already exists and this run did not create it; remove it first"
  record container "gtn-hs-$inst"
  docker start "gtn-hs-$inst" >/dev/null
  pid=$(docker inspect -f '{{.State.Pid}}' "gtn-hs-$inst")
  ip -n gtn-mgmt link add "m-hs-$inst" type veth peer name eth0 netns "$pid"
  ip -n gtn-mgmt link set "m-hs-$inst" master br0 up
  nsenter -t "$pid" -n ip addr add "$addr/64" dev eth0 nodad
  nsenter -t "$pid" -n ip addr add "$addr4/24" dev eth0
  nsenter -t "$pid" -n ip link set eth0 up
  wait_for 30 hs "$inst" users list
}

# host_vrf creates a canonical host VRF the way the CNI does: its own table
# with unreachable defaults behind every real route.
host_vrf() {
  local vpc=$1 table=${HOST_TABLE[$1]}
  ip -n gtn-node link add "vrf-$vpc" type vrf table "$table"
  ip -n gtn-node -6 route add unreachable default metric "$UNREACHABLE_METRIC" table "$table"
  ip -n gtn-node -4 route add unreachable default metric "$UNREACHABLE_METRIC" table "$table"
  ip -n gtn-node link set "vrf-$vpc" up
}

# workload attaches namespace gtn-wl-$1 to host VRF vrf-$1 the way the CNI's
# veth plugin attaches a pod: a /128, a permanent neighbor each way and a
# host route.
workload() {
  local vpc=$1 ns=wl-$1 hl=wl-$1 table=${HOST_TABLE[$1]}
  new_ns "$ns"
  ip -n gtn-node link add "$hl" type veth peer name eth0 netns "gtn-$ns"
  ip -n gtn-node link set "$hl" master "vrf-$vpc"
  ip -n gtn-node addr add fe80::1/64 dev "$hl" nodad
  ip -n gtn-node link set "$hl" up
  ip -n "gtn-$ns" addr add "$WORKLOAD/128" dev eth0 nodad
  ip -n "gtn-$ns" addr add fe80::2/64 dev eth0 nodad
  ip -n "gtn-$ns" link set eth0 up
  ip -n gtn-node -6 neigh replace "$WORKLOAD" lladdr "$(link_mac "$ns" eth0)" dev "$hl" nud permanent
  ip -n gtn-node -6 route replace "$WORKLOAD/128" dev "$hl" table "$table"
  ip -n "gtn-$ns" -6 neigh replace fe80::1 lladdr "$(link_mac node "$hl")" dev eth0 nud permanent
  ip -n "gtn-$ns" -6 route replace default via fe80::1 dev eth0
}

# pod_vrf creates the binding namespace's pod VRF and its tailscale0: a
# persistent TUN enslaved to the VRF, which tailscaled later opens by name,
# with the site prefix routed to it.
pod_vrf() {
  local ns=$1 id=$2
  ip -n "gtn-$ns" link add vrf-tn type vrf table "$POD_TABLE"
  ip -n "gtn-$ns" -6 route add unreachable default metric "$UNREACHABLE_METRIC" table "$POD_TABLE"
  ip -n "gtn-$ns" -4 route add unreachable default metric "$UNREACHABLE_METRIC" table "$POD_TABLE"
  ip -n "gtn-$ns" link set vrf-tn up
  ip -n "gtn-$ns" tuntap add dev tailscale0 mode tun
  ip -n "gtn-$ns" link set tailscale0 alias "$id" master vrf-tn up
  tun_routes "$ns"
  forwarding "$ns"
}

# tun_routes routes the site prefix to tailscale0 in the pod VRF.
tun_routes() {
  ip -n "gtn-$1" -6 route replace "$SITE_PREFIX" dev tailscale0 table "$POD_TABLE"
}

# attach provisions the host-owned attachment of binding gtn-$1 to VPC $2 with
# host link $3 and attachment ID $4. It refuses a host link that carries
# another ID, the way the attachment code does.
attach() {
  local ns=$1 vpc=$2 hl=$3 id=$4 table=${HOST_TABLE[$2]} alias
  if ip -n gtn-node link show "$hl" >/dev/null 2>&1; then
    alias=$(ip -n gtn-node -j link show "$hl" | jq -r '.[0].ifalias // ""')
    if [[ $alias != "$id" ]]; then
      say "  refused: host link $hl belongs to attachment '$alias'"
      return 1
    fi
  fi
  ip -n "gtn-$ns" link add att0 type veth peer name "$hl" netns gtn-node
  ip -n gtn-node link set "$hl" alias "$id" master "vrf-$vpc"
  ip -n gtn-node addr add fe80::1/64 dev "$hl" nodad
  ip -n gtn-node link set "$hl" up
  ip -n gtn-node -6 neigh replace "$ATTACH_ADDR" lladdr "$(link_mac "$ns" att0)" dev "$hl" nud permanent
  ip -n gtn-node -6 route replace "$ATTACH_ADDR/128" dev "$hl" table "$table"
  ip -n gtn-node -6 route replace "$SITE_PREFIX" via "$ATTACH_ADDR" dev "$hl" table "$table"
  ip -n "gtn-$ns" link set att0 master vrf-tn
  ip -n "gtn-$ns" addr add fe80::2/64 dev att0 nodad
  ip -n "gtn-$ns" addr add "$ATTACH_ADDR/128" dev att0 nodad
  ip -n "gtn-$ns" link set att0 up
  ip -n "gtn-$ns" -6 neigh replace fe80::1 lladdr "$(link_mac node "$hl")" dev att0 nud permanent
  ip -n "gtn-$ns" -6 route replace default via fe80::1 dev att0 table "$POD_TABLE"
}

# release removes the host end of an attachment, and with it every host route
# and neighbor through it, if it carries attachment ID $2.
release() {
  local hl=$1 id=$2 alias
  alias=$(ip -n gtn-node -j link show "$hl" | jq -r '.[0].ifalias // ""')
  if [[ $alias != "$id" ]]; then
    say "  refused: host link $hl belongs to attachment '$alias'"
    return 1
  fi
  ip -n gtn-node link del "$hl"
}

# audit counts the binding's own control and WireGuard packets that use the
# attachment or the pod VRF instead of the management interface.
audit() {
  local ns=$1
  nsx "$ns" nft -f - <<'EOF'
table inet gtn-audit {
  chain out {
    type filter hook output priority 0; policy accept;
    oifname { "att0", "vrf-tn" } udp dport { 41641, 3478 } counter name vpc_ctl
    oifname { "att0", "vrf-tn" } tcp dport 443 counter name vpc_ctl
    oifname "mgmt0" udp sport 41641 counter name mgmt_wg
  }
  counter vpc_ctl {}
  counter mgmt_wg {}
}
EOF
}
audit_count() { nsx "$1" nft -j list counter inet gtn-audit "$2" | jq '.nftables[1].counter.packets'; }

site() {
  local s=$1
  new_ns "site-$s"
  new_ns "shost-$s"
  mgmt_attach "site-$s"
  ip -n "gtn-site-$s" link add lan0 type veth peer name eth0 netns "gtn-shost-$s"
  ip -n "gtn-site-$s" addr add "$SITE_GW/64" dev lan0 nodad
  ip -n "gtn-site-$s" link set lan0 up
  ip -n "gtn-shost-$s" addr add "$SITE_HOST/64" dev eth0 nodad
  ip -n "gtn-shost-$s" link set eth0 up
  ip -n "gtn-shost-$s" -6 route add default via "$SITE_GW"
  forwarding "site-$s"
}

ts_start() {
  local name=$1
  mkdir -p "$WORK/state/$name" "$RUN" "$WORK/log"
  ip netns exec "gtn-$name" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    HOME="$WORK/state/$name" TS_LOGS_DIR="$WORK/state/$name" SSL_CERT_FILE="$WORK/pki/bundle.pem" \
    TS_DEBUG_FIREWALL_MODE=nftables DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent \
    "$BIN/tailscaled" --tun=tailscale0 --port=41641 \
    --statedir="$WORK/state/$name" --socket="$RUN/$name.sock" \
    --encrypt-state=false --syspolicy-file= --no-logs-no-support \
    >>"$WORK/log/$name.log" 2>&1 &
  echo $! >"$RUN/$name.pid"
  wait_for 30 ts "$name" status --json
}

ts_pid() { cat "$RUN/$1.pid"; }

user_id() { hs "$1" users list -o json | jq -r --arg n "$2" '.[] | select(.name == $n) | .id'; }
node_id() { hs "$1" nodes list -o json | jq -r --arg n "$2" '.[] | select(.given_name == $n or .name == $n) | .id'; }
authkey() { hs "$1" preauthkeys create -u "$(user_id "$1" "$2")" --expiration 1h -o json | jq -r .key; }

# ts_up enrolls tailscaled gtn-$1 into Headscale $2 as user $3, with any
# extra tailscale up flags.
ts_up() {
  local name=$1 inst=$2 user=$3
  shift 3
  ts "$name" up --login-server="https://[${MGMT_ADDR[hs-$inst]}]:443" \
    --auth-key="$(authkey "$inst" "$user")" --hostname="$name" \
    --accept-dns=false --timeout=60s "$@"
}

ts_ip6() { ts "$1" ip -6; }
# route_in_52 succeeds when gtn-$1 has imported prefix $2 into table 52.
route_in_52() { grep -q "^$2 dev tailscale0" <<<"$(ip -n "gtn-$1" -6 route show table 52)"; }
# reach succeeds when a TCP connection from gtn-$1 to the workload address is
# answered by the workload of VPC $2.
reach() {
  local got
  got=$(nsx "$1" python3 "$WORK/client.py" "$WORKLOAD" "$APP_PORT" 2>/dev/null) || return 1
  [[ $got == "vpc-$2" ]]
}
ping6() {
  local ns=$1
  shift
  nsx "$ns" ping -6 -n -q "$@"
}

write_helpers() {
  cat >"$WORK/server.py" <<'EOF'
import socket, sys
name, port, log = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("::", port))
s.listen(16)
while True:
    c, a = s.accept()
    with open(log, "a") as f:
        f.write(a[0] + "\n")
    c.sendall(name.encode() + b"\n")
    c.close()
EOF
  cat >"$WORK/client.py" <<'EOF'
import socket, sys
try:
    s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3)
    print(s.recv(64).decode().strip())
except OSError as e:
    print("error: %s" % e)
    sys.exit(1)
EOF
}

start_server() {
  local vpc=$1
  : >"$WORK/log/peers-$vpc.log"
  # ip netns exec, not nsx: a backgrounded function would leave $! naming a
  # subshell rather than the server.
  ip netns exec "gtn-wl-$vpc" python3 "$WORK/server.py" "vpc-$vpc" "$APP_PORT" "$WORK/log/peers-$vpc.log" &
  echo $! >"$RUN/server-$vpc.pid"
}

build() {
  step "Build the topology"
  rm -rf "$WORK/log"
  mkdir -p "$RUN" "$WORK/log"
  write_helpers
  new_ns mgmt
  ip -n gtn-mgmt link add br0 type bridge
  ip -n gtn-mgmt addr add "$MGMT_GW/64" dev br0 nodad
  ip -n gtn-mgmt addr add "$MGMT_GW4/24" dev br0
  ip -n gtn-mgmt link set br0 up
  headscale_up a
  headscale_up b
  new_ns node
  forwarding node
  host_vrf a
  host_vrf b
  workload a
  workload b
  site a
  site b
  local vpc
  for vpc in a b; do
    new_ns "bind-$vpc"
    mgmt_attach "bind-$vpc"
    pod_vrf "bind-$vpc" "attachment-$vpc-1"
    attach "bind-$vpc" "$vpc" "att-$vpc" "attachment-$vpc-1"
    audit "bind-$vpc"
    hs "$vpc" users create "tenant-$vpc" >/dev/null
    start_server "$vpc"
  done
  for vpc in a b; do
    ts_start "bind-$vpc"
    ts_start "site-$vpc"
  done
  say "built: two tailnets, two VPCs, workload $WORKLOAD in each"
}

# ---------------------------------------------------------------- checks

check_enroll() {
  step "1. Enrollment: one pre-auth key, node key, state and socket per binding"
  local vpc ok=true
  for vpc in a b; do
    ts_up "bind-$vpc" "$vpc" "tenant-$vpc" --advertise-routes="$VPC_PREFIX" \
      --snat-subnet-routes=false --accept-routes || ok=false
    ts_up "site-$vpc" "$vpc" "tenant-$vpc" --advertise-routes="$SITE_PREFIX" \
      --snat-subnet-routes=false --accept-routes || ok=false
  done
  local ka kb
  ka=$(ts bind-a status --json | jq -r .Self.PublicKey)
  kb=$(ts bind-b status --json | jq -r .Self.PublicKey)
  say "  bind-a: node key $ka, state $WORK/state/bind-a, socket $RUN/bind-a.sock, tailscaled pid $(ts_pid bind-a)"
  say "  bind-b: node key $kb, state $WORK/state/bind-b, socket $RUN/bind-b.sock, tailscaled pid $(ts_pid bind-b)"
  show ts bind-a status
  show ts bind-b status
  show hs a nodes list
  show hs b nodes list
  if $ok && [[ -n $ka && -n $kb && $ka != "$kb" ]] &&
    [[ $(ts bind-a status --json | jq -r .BackendState) == Running ]] &&
    [[ $(ts bind-b status --json | jq -r .BackendState) == Running ]]; then
    result PASS 1 "each binding enrolled with its own key into its own tailnet; node keys differ"
  else
    result FAIL 1 "enrollment"
  fi
}

check_routes() {
  step "2. Route export needs Headscale approval; site routes are imported"
  local vpc
  # Approve the sites first, so the only missing piece is the binding's route.
  for vpc in a b; do
    hs "$vpc" nodes approve-routes -i "$(node_id "$vpc" "site-$vpc")" -r "$SITE_PREFIX" >/dev/null
  done
  wait_for 30 route_in_52 bind-a "$SITE_PREFIX" || true
  sleep 3
  show hs a nodes list-routes
  local before_routed=false before_reach=false
  route_in_52 site-a "$VPC_PREFIX" && before_routed=true
  reach shost-a a && before_reach=true
  say "  before approval: site-a has $VPC_PREFIX in table 52: $before_routed; site host reaches workload: $before_reach"
  show ip -n gtn-site-a -6 route show table 52
  for vpc in a b; do
    hs "$vpc" nodes approve-routes -i "$(node_id "$vpc" "bind-$vpc")" -r "$VPC_PREFIX" >/dev/null
  done
  wait_for 30 route_in_52 site-a "$VPC_PREFIX" || true
  wait_for 30 route_in_52 site-b "$VPC_PREFIX" || true
  show hs a nodes list-routes
  show ip -n gtn-site-a -6 route show table 52
  show ip -n gtn-bind-a -6 route show table 52
  local imported=false after=false
  route_in_52 bind-a "$SITE_PREFIX" && route_in_52 bind-b "$SITE_PREFIX" && imported=true
  wait_for 20 reach shost-a a && after=true
  say "  after approval: site-a has $VPC_PREFIX: $(route_in_52 site-a "$VPC_PREFIX" && echo true || echo false); bindings imported $SITE_PREFIX: $imported; site host reaches workload: $after"
  if ! $before_routed && ! $before_reach && $imported && $after; then
    result PASS 2 "binding route unrouted until approve-routes, routed after; site prefix imported with --accept-routes; SNAT off"
  else
    result FAIL 2 "before routed=$before_routed reach=$before_reach; after imported=$imported reach=$after"
  fi
}

check_vrf() {
  step "3. tailscale0 in the pod VRF: tenant traffic in the VRF, transport on mgmt0"
  show ip -n gtn-bind-a -d link show tailscale0
  show ip -n gtn-bind-a rule show
  show ip -n gtn-bind-a -6 rule show
  show ip -n gtn-bind-a -6 route show table "$POD_TABLE"
  show ip -n gtn-bind-a -6 route show table 52
  show ip -n gtn-bind-a -6 route show table main
  show nsx bind-a nft list ruleset
  grep -m1 -E 'firewall|nftables|iptables' "$WORK/log/bind-a.log" | sed 's/^/  log: /' || true
  local master ctl wg
  master=$(ip -n gtn-bind-a -j -d link show tailscale0 | jq -r '.[0].master // ""')
  ctl=$(audit_count bind-a vpc_ctl)
  wg=$(audit_count bind-a mgmt_wg)
  say "  tailscale0 master: $master; control/WireGuard packets out att0 or vrf-tn: $ctl; WireGuard packets out mgmt0: $wg"

  # Restarting tailscaled leaves the persistent TUN, and its VRF membership,
  # in place, but tailscaled sets the link down on exit, and the kernel drops
  # every route through a link that goes down. The attachment owner has to
  # put the pod VRF's routes back once tailscaled is up again.
  local pre=false old_idx new_idx
  reach shost-a a && pre=true
  old_idx=$(ip -n gtn-bind-a -j link show tailscale0 | jq -r '.[0].ifindex')
  kill "$(ts_pid bind-a)"
  wait_for 10 sh -c "! kill -0 $(ts_pid bind-a) 2>/dev/null" || true
  say "  tailscaled stopped; tailscale0 and the pod VRF's routes through it:"
  show ip -n gtn-bind-a -d link show tailscale0
  show ip -n gtn-bind-a -6 route show table "$POD_TABLE" dev tailscale0
  ts_start bind-a
  wait_for 30 sh -c "ip netns exec gtn-bind-a $BIN/tailscale --socket=$RUN/bind-a.sock status --json | jq -e '.BackendState == \"Running\"'" || true
  new_idx=$(ip -n gtn-bind-a -j link show tailscale0 | jq -r '.[0].ifindex')
  local remaster lost=false restored=false
  remaster=$(ip -n gtn-bind-a -j -d link show tailscale0 | jq -r '.[0].master // ""')
  show ip -n gtn-bind-a -6 route show table "$POD_TABLE" dev tailscale0
  if ! grep -q "^$SITE_PREFIX dev tailscale0" <<<"$(ip -n gtn-bind-a -6 route show table "$POD_TABLE")" &&
    ! reach shost-a a; then
    lost=true
  fi
  tun_routes bind-a
  wait_for 30 reach shost-a a && restored=true
  say "  forwarding before restart: $pre; ifindex $old_idx -> $new_idx, master after restart: $remaster"
  say "  after restart, pod VRF route and forwarding lost: $lost; after the owner restores the route: $restored"

  # The binding's own tailnet addresses sit on a VRF slave, so the pod VRF
  # table, which has no route back into the tailnet range, routes the replies.
  # IPv4 is also dropped earlier: tailscaled's input chain drops 100.64.0.0/10
  # unless it arrives on tailscale0, and a VRF slave's packets arrive on the
  # VRF device.
  local v4 own4=false own6=false
  v4=$(ts bind-a ip -4)
  ping6 site-a -c 2 -W 2 "$(ts_ip6 bind-a)" >/dev/null 2>&1 && own6=true
  nsx site-a ping -4 -n -q -c 2 -W 2 "$v4" >/dev/null 2>&1 && own4=true
  say "  site-a -> binding's own tailnet address: IPv6 $own6, IPv4 $own4"
  show nsx bind-a nft list chain ip filter ts-input
  if [[ $pre == true && $master == vrf-tn && $remaster == vrf-tn && $ctl == 0 && $wg -gt 0 &&
    $old_idx == "$new_idx" && $lost == true && $restored == true ]]; then
    result PASS 3 "pre-created TUN in the pod VRF forwards; tailscaled reopens it on restart but its routes must be restored; transport stays on mgmt0 (own tailnet IPv4 reachable: $own4, IPv6: $own6)"
  else
    result FAIL 3 "pre=$pre master=$master remaster=$remaster vpc_ctl=$ctl mgmt_wg=$wg ifindex $old_idx->$new_idx lost=$lost restored=$restored"
  fi
}

check_source() {
  step "4. Source preservation and return path"
  : >"$WORK/log/peers-a.log"
  local reply cap
  cap=$WORK/log/wl-a.pcap
  nsx wl-a timeout 8 tcpdump -Z root -ni eth0 -c 2 -w "$cap" 'icmp6 and ip6[40] == 128' >/dev/null 2>&1 &
  local tpid=$!
  sleep 1
  show ping6 shost-a -c 2 "$WORKLOAD"
  reply=$(nsx shost-a python3 "$WORK/client.py" "$WORKLOAD" "$APP_PORT" 2>&1 || true)
  wait "$tpid" || true
  show tcpdump -Z root -nr "$cap"
  say "  TCP reply: $reply; peers seen by the VPC A workload: $(sort -u "$WORK/log/peers-a.log" | tr '\n' ' ')"
  show ip -n gtn-node -6 route show table "${HOST_TABLE[a]}"
  if [[ $reply == vpc-a ]] && grep -qx "$SITE_HOST" "$WORK/log/peers-a.log" &&
    tcpdump -Z root -nr "$cap" 2>/dev/null | grep -q "$SITE_HOST > $WORKLOAD"; then
    result PASS 4 "workload sees source $SITE_HOST (ICMP and TCP); replies return through the attachment"
  else
    result FAIL 4 "reply=$reply peers=$(tr '\n' ' ' <"$WORK/log/peers-a.log")"
  fi
}

check_isolation() {
  step "5. Isolation between VPCs with identical addresses"
  : >"$WORK/log/peers-a.log"
  : >"$WORK/log/peers-b.log"
  local rx_b0 rx_b1 ra rb
  rx_b0=$(link_counter bind-b tailscale0 rx)
  ra=$(nsx shost-a python3 "$WORK/client.py" "$WORKLOAD" "$APP_PORT" 2>&1 || true)
  ping6 shost-a -c 3 "$WORKLOAD" >/dev/null 2>&1 || true
  rx_b1=$(link_counter bind-b tailscale0 rx)
  rb=$(nsx shost-b python3 "$WORK/client.py" "$WORKLOAD" "$APP_PORT" 2>&1 || true)
  say "  site A host -> $WORKLOAD answered by: $ra; site B host -> $WORKLOAD answered by: $rb"
  say "  bind-b tailscale0 rx packets while site A sent: $rx_b0 -> $rx_b1"
  say "  peers seen by VPC A: $(tr '\n' ' ' <"$WORK/log/peers-a.log"); by VPC B: $(tr '\n' ' ' <"$WORK/log/peers-b.log")"
  show ts site-a status
  local peers_a
  peers_a=$(ts site-a status --json | jq -r '[.Peer[].HostName] | join(",")')
  if [[ $ra == vpc-a && $rb == vpc-b && $rx_b0 == "$rx_b1" && $peers_a == bind-a ]]; then
    result PASS 5 "site A reaches only VPC A, site B only VPC B; binding B received none of A's packets"
  else
    result FAIL 5 "ra=$ra rb=$rb bind-b rx $rx_b0->$rx_b1 site-a peers=$peers_a"
  fi

  step "5b. One Headscale serving both tenants: overlapping prefixes"
  # A node of another user in tailnet A advertises the same site prefix and
  # is approved. Headscale elects one primary per prefix across all users.
  new_ns probe
  mgmt_attach probe
  ip -n gtn-probe link add lan0 type dummy
  ip -n gtn-probe addr add "$SITE_GW/64" dev lan0 nodad
  ip -n gtn-probe link set lan0 up
  forwarding probe
  ts_start probe
  hs a users create intruder >/dev/null
  ts_up probe a intruder --advertise-routes="$SITE_PREFIX" --snat-subnet-routes=false >/dev/null
  hs a nodes approve-routes -i "$(node_id a probe)" -r "$SITE_PREFIX" >/dev/null
  sleep 3
  show hs a nodes list-routes
  local primary
  primary=$(hs a nodes list-routes -o json | jq -r --arg p "$SITE_PREFIX" \
    '.[] | select((.subnet_routes // []) | index($p)) | .given_name' | paste -sd,)
  say "  primary for $SITE_PREFIX in tailnet A: $primary"
  # The probe has no IPv4 address; every runtime above is dual-stack.
  sleep 45
  local rb_probe rb_bind
  rb_probe=$(grep -c 'last netcheck reported send error. Rebinding' "$WORK/log/probe.log" || true)
  rb_bind=$(grep -c 'last netcheck reported send error. Rebinding' "$WORK/log/bind-a.log" || true)
  ts probe logout >/dev/null 2>&1 || true
  kill "$(ts_pid probe)" 2>/dev/null || true
  if [[ $primary == site-a ]]; then
    result PASS 5b "a shared Headscale treats the other tenant's overlapping prefix as an HA standby of the same route, so tenants with overlapping prefixes need separate tailnets"
  else
    result FAIL 5b "primary=$primary"
  fi
  say "  magicsock rebinds for lack of IPv4: IPv6-only probe $rb_probe, dual-stack bind-a $rb_bind"
  result NOTE 5c "IPv6-only runtime rebinds and resets peer paths repeatedly ($rb_probe rebinds in its first minute; dual-stack bind-a over the whole run: $rb_bind)"
}

# path_kind prints direct or relay for the path from gtn-$1 to tailnet peer $2.
path_kind() {
  local out
  out=$(ts "$1" ping --c 1 --timeout 3s "$2" 2>&1 || true)
  case $out in
    *"via DERP"*) echo relay ;;
    *"pong from"*) echo direct ;;
    *) echo none ;;
  esac
}

big_ping() {
  local from=$1 to=$2 size=$3
  nsx "$from" ping -6 -n -c 3 -W 2 -M "do" -s "$size" "$to"
}

check_paths() {
  step "6. Direct and DERP-only paths, 1280-byte packets"
  local peer mtu_b mtu_s d_kind r_kind d_big=false r_big=false d_small=false r_small=false
  peer=$(ts_ip6 bind-a)
  mtu_b=$(ip -n gtn-bind-a -j link show tailscale0 | jq -r '.[0].mtu')
  mtu_s=$(ip -n gtn-site-a -j link show tailscale0 | jq -r '.[0].mtu')
  say "  tailscale0 MTU: binding $mtu_b, site $mtu_s"
  wait_for 20 sh -c "$BIN/tailscale --socket=$RUN/site-a.sock ping --c 1 --timeout 3s $peer 2>&1 | grep -q 'pong from' && ! $BIN/tailscale --socket=$RUN/site-a.sock ping --c 1 --timeout 3s $peer 2>&1 | grep -q DERP" || true
  d_kind=$(path_kind site-a "$peer")
  show ts site-a ping --c 2 "$peer"
  ping6 shost-a -c 3 "$WORKLOAD" >/dev/null 2>&1 && d_small=true
  show big_ping shost-a "$WORKLOAD" 1232
  big_ping shost-a "$WORKLOAD" 1232 >/dev/null 2>&1 && d_big=true
  say "  above the MTU, site host -> workload (1281-byte packet):"
  show big_ping shost-a "$WORKLOAD" 1233
  say "  above the MTU, workload -> site host:"
  show big_ping wl-a "$SITE_HOST" 1233

  # Block UDP between the two runtimes' management addresses, in both
  # namespaces, so only the DERP relay over TCP 443 remains.
  local ns other
  for ns in bind-a site-a; do
    other=site-a
    [[ $ns == site-a ]] && other=bind-a
    nsx "$ns" nft -f - <<EOF
table inet gtn-relay {
  chain out {
    type filter hook output priority -10; policy accept;
    ip6 daddr ${MGMT_ADDR[$other]} meta l4proto udp counter drop
    ip daddr ${MGMT_ADDR4[$other]} meta l4proto udp counter drop
  }
  chain in {
    type filter hook input priority -10; policy accept;
    ip6 saddr ${MGMT_ADDR[$other]} meta l4proto udp counter drop
    ip saddr ${MGMT_ADDR4[$other]} meta l4proto udp counter drop
  }
}
EOF
  done
  wait_for 40 sh -c "$BIN/tailscale --socket=$RUN/site-a.sock ping --c 1 --timeout 3s $peer 2>&1 | grep -q 'via DERP'" || true
  r_kind=$(path_kind site-a "$peer")
  show ts site-a ping --c 2 "$peer"
  show ts site-a status
  wait_for 10 ping6 shost-a -c 1 -W 2 "$WORKLOAD" && r_small=true
  show big_ping shost-a "$WORKLOAD" 1232
  big_ping shost-a "$WORKLOAD" 1232 >/dev/null 2>&1 && r_big=true
  show nsx bind-a nft list table inet gtn-relay
  for ns in bind-a site-a; do
    nsx "$ns" nft delete table inet gtn-relay
  done
  say "  direct: path=$d_kind ping=$d_small 1280B=$d_big; relay: path=$r_kind ping=$r_small 1280B=$r_big"
  if [[ $d_kind == direct && $r_kind == relay ]] && $d_small && $d_big && $r_small && $r_big; then
    result PASS 6 "direct and DERP-only paths both deliver, including 1280-byte packets; tailscale0 MTU $mtu_b"
  else
    result FAIL 6 "direct=$d_kind/$d_small/$d_big relay=$r_kind/$r_small/$r_big"
  fi
}

check_replace() {
  step "8. Replacement binding with a new node key; one forwarding owner"
  new_ns bind-a2
  mgmt_attach bind-a2
  pod_vrf bind-a2 attachment-a-2
  ts_start bind-a2
  ts_up bind-a2 a tenant-a --advertise-routes="$VPC_PREFIX" --snat-subnet-routes=false --accept-routes >/dev/null
  local id1 id2 k1 k2
  id1=$(node_id a bind-a)
  id2=$(node_id a bind-a2)
  hs a nodes approve-routes -i "$id2" -r "$VPC_PREFIX" >/dev/null
  sleep 3
  k1=$(ts bind-a status --json | jq -r .Self.PublicKey)
  k2=$(ts bind-a2 status --json | jq -r .Self.PublicKey)
  say "  bind-a node $id1 key $k1; bind-a2 node $id2 key $k2 (fresh state dir $WORK/state/bind-a2)"
  show hs a nodes list-routes
  local p1
  p1=$(hs a nodes list-routes -o json | jq -r --arg p "$VPC_PREFIX" \
    '.[] | select((.subnet_routes // []) | index($p)) | .given_name' | paste -sd,)

  say "  the replacement cannot take the old attachment's host link:"
  local refused=false
  attach bind-a2 a att-a attachment-a-2 || refused=true

  say "  release the old attachment (host link att-a):"
  release att-a attachment-a-1
  local gap=true
  reach shost-a a && gap=false
  say "  site host reaches workload with the old node still primary and unattached: $([[ $gap == true ]] && echo false || echo true)"

  attach bind-a2 a att-a2 attachment-a-2
  audit bind-a2
  hs a nodes approve-routes -i "$id1" -r "" >/dev/null
  local moved=false rx1 rx2 rx1b rx2b
  wait_for 30 reach shost-a a && moved=true
  rx1=$(link_counter bind-a tailscale0 rx)
  rx2=$(link_counter bind-a2 tailscale0 rx)
  ping6 shost-a -c 5 "$WORKLOAD" >/dev/null 2>&1 || true
  rx1b=$(link_counter bind-a tailscale0 rx)
  rx2b=$(link_counter bind-a2 tailscale0 rx)
  show hs a nodes list-routes
  local p2
  p2=$(hs a nodes list-routes -o json | jq -r --arg p "$VPC_PREFIX" \
    '.[] | select((.subnet_routes // []) | index($p)) | .given_name' | paste -sd,)
  say "  after unapproving bind-a: primary $p2; tailscale0 rx bind-a $rx1 -> $rx1b, bind-a2 $rx2 -> $rx2b; old tailscaled alive: $(kill -0 "$(ts_pid bind-a)" && echo yes)"
  say "  the state file carries the node identity (key names only):"
  show sh -c "jq -r 'keys[]' '$WORK/state/bind-a/tailscaled.state'"
  if [[ $k1 != "$k2" && $p1 == bind-a && $refused == true && $gap == true && $moved == true && $p2 == bind-a2 && $rx1 == "$rx1b" && $rx2b -gt $rx2 ]]; then
    result PASS 8 "new key enrolls as an HA standby; Headscale's primary, not the attachment, picks the tailnet owner; moving it takes unapproving the old node"
  else
    result FAIL 8 "k1!=k2 $([[ $k1 != "$k2" ]] && echo y) p1=$p1 refused=$refused gap=$gap moved=$moved p2=$p2 rx1 $rx1->$rx1b rx2 $rx2->$rx2b"
  fi
}

# forwarding_for pings the workload from the site host for $1 seconds and
# prints how many replies came back.
forwarding_for() {
  local out
  out=$(ping6 shost-a -c "$1" -i 1 -W 1 "$WORKLOAD" 2>/dev/null || true)
  awk '/received/ {print $4}' <<<"$out"
}

check_expiry() {
  step "7. Control-plane loss and local expiry"
  local b=bind-a2 hl=att-a2 id=attachment-a-2
  wait_for 20 reach shost-a a || true
  docker stop -t 2 gtn-hs-a >/dev/null
  say "  Headscale A stopped"
  local got
  got=$(forwarding_for 20)
  show ts "$b" status
  say "  replies during 20 s without control plane: $got/20"

  nsx "$b" nft -f - <<'EOF'
table inet gtn-expiry {
  chain forward_drop {
    type filter hook forward priority -300; policy accept;
    iifname { "tailscale0", "vrf-tn" } counter drop
    oifname "tailscale0" counter drop
  }
}
EOF
  local nft_got alive1
  nft_got=$(forwarding_for 5)
  kill -0 "$(ts_pid "$b")" && alive1=yes || alive1=no
  show nsx "$b" nft list table inet gtn-expiry
  say "  binding-namespace drop: replies $nft_got/5, tailscaled alive: $alive1"
  nsx "$b" nft delete table inet gtn-expiry
  local resumed
  resumed=$(forwarding_for 5)
  say "  drop removed: replies $resumed/5"

  release "$hl" "$id"
  local att_got alive2
  att_got=$(forwarding_for 5)
  kill -0 "$(ts_pid "$b")" && alive2=yes || alive2=no
  show ip -n gtn-node -6 route show table "${HOST_TABLE[a]}"
  say "  host attachment released: replies $att_got/5, tailscaled alive: $alive2"
  show ts "$b" status
  if ((got >= 18)) && [[ $nft_got == 0 && $alive1 == yes && $resumed -ge 4 && $att_got == 0 && $alive2 == yes ]]; then
    result PASS 7 "forwarding survives control-plane loss; an nft drop in the binding namespace or releasing the host attachment stops it while tailscaled keeps running"
  else
    result FAIL 7 "no-control=$got/20 nft=$nft_got alive=$alive1 resumed=$resumed released=$att_got alive=$alive2"
  fi
}

summary() {
  step "Summary"
  result BLOCKED H "hosted Tailscale control plane: deferred, not attempted"
  local changes
  if changes=$(guard_changed); then
    say "$changes"
    result FAIL G "host files changed during the run: ${GUARD_FILES[*]}"
    GUARD_FAILED=true
  else
    result PASS G "host files unchanged: ${GUARD_FILES[*]}"
  fi
  printf '\n'
  printf '%s\n' "${RESULTS[@]}"
}

GUARD_FAILED=false

main() {
  preflight
  setup_state
  if [[ ${mode:-} == down ]]; then
    cleanup
    exit 0
  fi
  check_dir "$WORK"
  modprobe vrf
  modprobe tun
  step "Clean up earlier runs"
  cleanup
  setup_work
  GUARD_BEFORE=$(fingerprint)
  say "work directory: $WORK"
  say "host file baseline:"
  printf '%s\n' "$GUARD_BEFORE" | sed 's/^/  /'
  if ! $keep; then
    trap on_exit EXIT
  fi
  step "Pinned versions"
  fetch
  pki
  build
  check_enroll
  check_routes
  check_vrf
  check_source
  check_isolation
  check_paths
  check_replace
  check_expiry
  summary
  if $GUARD_FAILED; then
    exit 1
  fi
}

main
