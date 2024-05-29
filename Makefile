default: build

BPF_PROG = kernel-cwnd.bpf.c
BUILD_NAME = bpfiw

build: $(BPF_PROG) vmlinux.h clean
	mkdir -p build
	clang \
		-target bpf \
		-D __TARGET_ARCH_$(ARCH) \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g -O2 -c $(BPF_PROG) -o ./build/$(BUILD_NAME).o
	llvm-strip -g ./build/$(BUILD_NAME).o

vmlinux.h:
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./vmlinux.h

load:
	sudo bash ./load.sh

trace:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

unload:
	sudo bash ./unload.sh

show:
	sudo bpftool prog show name bpf_iw --pretty

clean: 
	rm -rf ./build/*
