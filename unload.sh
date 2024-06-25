#!/bin/bash
set -x

BUILD_NAME=bpf_sockops

sudo bpftool cgroup detach /sys/fs/cgroup/ sock_ops pinned /sys/fs/bpf/${BUILD_NAME}
sudo unlink /sys/fs/bpf/${BUILD_NAME}
sudo rm -rf /sys/fs/bpf/*
