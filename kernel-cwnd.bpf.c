/*
 * script to update congestion window using eBPF map
 * set value in map using bpftool map update
 */


/* Copyright (c) 2017 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * BPF program to set initial congestion window and initial receive
 * window to 40 packets and send and receive buffers to 1.5MB. This
 * would usually be done after doing appropriate checks that indicate
 * the hosts are far enough away (i.e. large RTT).
 *
 * Use "bpftool cgroup attach $cg sock_ops $prog" to load this BPF program.
 */

#include <linux/bpf.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <netinet/tcp.h> 
#include <arpa/inet.h>
#include "vmlinux.h"

#define DEBUG 1

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} wnd_map SEC(".maps");

SEC("sockops")
int bpf_iw(struct bpf_sock_ops *skops) {
	int ret = 0; // return value 
	struct in_addr addr;
	int key = 0, val = 0, op, *user_wnd;

	addr.s_addr = skops->remote_ip4;

	op = (int) skops->op;
	// if op neither active nor passive TCP connection; skip
	if (op != 4 && op != 5) return 0;

#ifdef DEBUG
	bpf_printk("Opcode: %d\n", op);
#endif

	switch (op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		user_wnd = bpf_map_lookup_elem(&wnd_map, &key);
		if (!user_wnd) {
			// if key not present in the map
			ret = bpf_map_update_elem(&wnd_map, &key, &val, BPF_NOEXIST);
			if (!ret) bpf_printk("Log: Screw BPF. ReturnVal(%d)", ret);
		}  else {
			// userspace has defined cwnd in map
			if (!*user_wnd) return 0;
			ret = bpf_setsockopt(skops, SOL_TCP, TCP_BPF_IW, user_wnd, sizeof(int));
			if (!ret) bpf_printk("Error: Socket cwnd not set. SockErr(%d)", ret);
			bpf_printk("InitCwnd(%d), IP(%pI4)", *user_wnd, &addr.s_addr);
		}
		break;
	}
#ifdef DEBUG
	bpf_printk("ReturnVal(%d)\n", ret);
#endif
	skops->reply = ret;
	return 1;
}

char _license[] SEC("license") = "GPL";
