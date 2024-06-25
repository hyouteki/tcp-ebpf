#!/bin/bash
set -xe

BUILD_NAME=bpf_sockops

sudo mount -t bpf bpf /sys/fs/bpf/

if [ -e "/sys/fs/bpf/bpf_sockops" ]; then
    echo "info: "${BUILD_NAME}" already loaded"
    ./unload.sh
    echo "info: old "${BUILD_NAME}" build unloaded"
fi

sudo bpftool prog load ./build/${BUILD_NAME}.o /sys/fs/bpf/${BUILD_NAME} type sockops pinmaps /sys/fs/bpf/
sudo bpftool cgroup attach /sys/fs/cgroup/ sock_ops pinned /sys/fs/bpf/${BUILD_NAME}
