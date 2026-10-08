//go:build linux

// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

const (
	ipAdd           = "add"
	ipRoute         = "route"
	ipTable         = "table"
	producerGateway = "fd00:da:1::1"
	ipLink          = "link"
	ipSet           = "set"
	ipVia           = "via"
	consumerCIDR    = "fd00:c::2/128"
	ipNetNS         = "netns"
	ipAddr          = "addr"
	ipExec          = "exec"
	ipDevice        = "dev"
	ipName          = "name"
	ipType          = "type"
	ipVeth          = "veth"
	ipPeer          = "peer"
	ipNoDAD         = "nodad"
	ipDefault       = "default"
	ipReplace       = "replace"
	servicePort     = "8443"
	relayTable      = "100"
)
