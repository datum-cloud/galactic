#!/bin/sh

log() {
  echo "$(hostname)-startup: $*"
}

wait_for_interface() {
  iface="$1"; timeout="${2:-30}"; i=0
  while [ "$i" -lt "$timeout" ]; do
    if ip link show dev "$iface" >/dev/null 2>&1; then
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  log "interface $iface did not appear within ${timeout}s"
  return 1
}

wait_for_gobgpd() {
  timeout="${1:-30}"; i=0
  while [ "$i" -lt "$timeout" ]; do
    if gobgp neighbor >/dev/null 2>&1; then
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  log "gobgpd did not become ready within ${timeout}s"
  return 1
}

wait_for_addr() {
  addr="$1"; timeout="${2:-30}"; i=0
  while [ "$i" -lt "$timeout" ]; do
    if ip -6 addr show to "$addr" scope global 2>/dev/null | grep -v tentative | grep -q inet6; then
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  log "address $addr did not appear within ${timeout}s"
  return 1
}

wait_for_route() {
  addr="$1"; timeout="${2:-120}"; i=0
  while [ "$i" -lt "$timeout" ]; do
    if ip -6 route get "$addr" >/dev/null 2>&1; then
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  log "route to $addr did not appear within ${timeout}s"
  return 1
}
