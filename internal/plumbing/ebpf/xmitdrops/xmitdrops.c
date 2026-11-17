//go:build ignore

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// xmitdrops counts the XDP redirects the kernel fails after an XDP program has
// returned XDP_REDIRECT. Neither failure is visible to the program itself:
//
//   - xdp_redirect_err fires when xdp_do_redirect cannot queue the frame, for
//     example because the target device implements no ndo_xdp_xmit.
//   - xdp_devmap_xmit fires when the queued frames are flushed to the target's
//     ndo_xdp_xmit, and reports how many of them the driver dropped, for
//     example because its XDP transmit queues are full.
//
// Both are attached as raw tracepoints, by name, so no tracefs mount is
// needed. Their arguments are the tracepoints' TP_PROTO, and device fields are
// read through CO-RE relocations against the running kernel's BTF.
//
// The tracepoints fire for every network namespace, and an ifindex means
// something only within one, so only drops whose target is in the namespace
// set in xmit_config are counted. Neither tracepoint reliably names the
// redirecting program: under the XDP dispatcher, xdp_redirect_err names the
// dispatcher, and xdp_devmap_xmit names none. Drops are therefore keyed by the
// target interface and the error alone.

#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) =
	(void *) BPF_FUNC_map_update_elem;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) =
	(void *) BPF_FUNC_probe_read_kernel;

// Only the fields read here are declared. preserve_access_index makes every
// access a CO-RE relocation, resolved against the kernel's own layout at load.
struct ns_common {
	unsigned int inum;
} __attribute__((preserve_access_index));

struct net {
	struct ns_common ns;
} __attribute__((preserve_access_index));

typedef struct {
	struct net *net;
} possible_net_t;

struct net_device {
	int ifindex;
	possible_net_t nd_net;
} __attribute__((preserve_access_index));

struct bpf_dtab_netdev {
	struct net_device *dev;
} __attribute__((preserve_access_index));

// Stages a drop is counted under.
enum xmit_drop_stage {
	XMIT_STAGE_REDIRECT = 0, // xdp_redirect_err
	XMIT_STAGE_XMIT     = 1, // xdp_devmap_xmit
};

// struct xmit_cfg, xmit_config's one value, is written once by userspace.
// netns_inum is the inode of the network namespace whose interfaces are
// counted; 0 counts every namespace.
struct xmit_cfg {
	__u32 netns_inum;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct xmit_cfg);
} xmit_config SEC(".maps");

// struct xmit_drop_key identifies one drop counter: the interface the frame was
// redirected to, 0 when it cannot be read, the stage that dropped it, and the
// positive errno the kernel reported, 0 when a driver dropped frames without
// one.
struct xmit_drop_key {
	__u32 ifindex;
	__u32 stage;
	__u32 err;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 1024);
	__type(key, struct xmit_drop_key);
	__type(value, __u64);
} xmit_drops SEC(".maps");

static __attribute__((always_inline)) inline __u32 dev_ifindex(const struct net_device *dev)
{
	int ifindex = 0;
	if (dev)
		bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex);
	return (__u32) ifindex;
}

// counted reports whether dev is in the configured network namespace.
static __attribute__((always_inline)) inline int counted(const struct net_device *dev)
{
	__u32 zero = 0;
	struct xmit_cfg *cfg = bpf_map_lookup_elem(&xmit_config, &zero);
	if (!cfg || cfg->netns_inum == 0)
		return 1;
	if (!dev)
		return 0;
	struct net *net = 0;
	unsigned int inum = 0;
	bpf_probe_read_kernel(&net, sizeof(net), &dev->nd_net.net);
	if (!net)
		return 0;
	bpf_probe_read_kernel(&inum, sizeof(inum), &net->ns.inum);
	return inum == cfg->netns_inum;
}

static __attribute__((always_inline)) inline void count(__u32 ifindex, __u32 stage, int err, __u64 n)
{
	struct xmit_drop_key key = {
		.ifindex = ifindex,
		.stage   = stage,
		.err     = (__u32) (err < 0 ? -err : err),
	};
	__u64 *value = bpf_map_lookup_elem(&xmit_drops, &key);
	if (value) {
		*value += n;
		return;
	}
	// Another CPU may insert the key first, so on failure add to its entry. A
	// full map loses this count rather than evicting another.
	if (bpf_map_update_elem(&xmit_drops, &key, &n, BPF_NOEXIST) == 0)
		return;
	value = bpf_map_lookup_elem(&xmit_drops, &key);
	if (value)
		*value += n;
}

// TP_PROTO(const struct net_device *dev, const struct bpf_prog *xdp,
//          const void *tgt, int err, enum bpf_map_type map_type,
//          u32 map_id, u32 index)
//
// For a plain bpf_redirect, map_type is BPF_MAP_TYPE_UNSPEC and index is the
// target ifindex, looked up in dev's own namespace. For a devmap, tgt is the
// map entry, which holds the target device.
SEC("raw_tracepoint/xdp_redirect_err")
int xdp_redirect_err(struct bpf_raw_tracepoint_args *ctx)
{
	const struct net_device *dev = (const void *) ctx->args[0];
	const void *tgt              = (const void *) ctx->args[2];
	int err                      = (int) ctx->args[3];
	__u32 map_type               = (__u32) ctx->args[4];
	__u32 index                  = (__u32) ctx->args[6];

	if (map_type == BPF_MAP_TYPE_UNSPEC) {
		if (counted(dev))
			count(index, XMIT_STAGE_REDIRECT, err, 1);
		return 0;
	}
	if ((map_type == BPF_MAP_TYPE_DEVMAP || map_type == BPF_MAP_TYPE_DEVMAP_HASH) && tgt) {
		const struct bpf_dtab_netdev *dst = tgt;
		struct net_device *to = 0;
		bpf_probe_read_kernel(&to, sizeof(to), &dst->dev);
		if (counted(to))
			count(dev_ifindex(to), XMIT_STAGE_REDIRECT, err, 1);
		return 0;
	}
	// Any other map type redirects to something that is not an interface.
	return 0;
}

// TP_PROTO(const struct net_device *from_dev, const struct net_device *to_dev,
//          int sent, int drops, int err)
SEC("raw_tracepoint/xdp_devmap_xmit")
int xdp_devmap_xmit(struct bpf_raw_tracepoint_args *ctx)
{
	const struct net_device *to = (const void *) ctx->args[1];
	int drops                   = (int) ctx->args[3];
	if (drops <= 0 || !counted(to))
		return 0;
	count(dev_ifindex(to), XMIT_STAGE_XMIT, (int) ctx->args[4], (__u64) drops);
	return 0;
}

char _license[] SEC("license") = "GPL";
