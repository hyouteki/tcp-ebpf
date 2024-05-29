#!/bin/bash
set -x
set -e

sudo mount -t bpf bpf /sys/fs/bpf/

# check if old program already loaded
if [ -e "/sys/fs/bpf/bpf_sockops" ]; then
    echo ">>> bpf_sockops already loaded, uninstalling..."
    ./unload.sh
    echo ">>> old program already deleted..."
fi

# create vmlinux.h if not already exists
if [ ! -e "./vmlinux.h" ]; then
    sudo bpftool dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
fi

# load and attach sock_ops program
sudo bpftool prog load haha.o /sys/fs/bpf/bpf_sockops type sockops pinmaps /sys/fs/bpf/
sudo bpftool cgroup attach "/sys/fs/cgroup/" sock_ops pinned "/sys/fs/bpf/bpf_sockops"
