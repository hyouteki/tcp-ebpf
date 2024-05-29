default: build

build: kernel-cend.bpf.c clean
	clang -O2 -g -Wall -emit-llvm -c kernel-cwnd.bpf.c -o haha.bc
	llc -march=bpf -mcpu=probe -filetype=obj haha.bc -o haha.o

load:
	sudo bash ./load.sh

trace:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

unload:
	sudo bash ./unload.sh

show:
	sudo bpftool prog show name bpf_iw --pretty

clean: 
	rm -rf haha.o haha.bc
