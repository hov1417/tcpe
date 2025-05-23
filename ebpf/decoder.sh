clang -O2 -g -target bpf -c decoder.c -o decoder.o -DTRACE_PORTS=8080
bpftool cgroup detach /sys/fs/cgroup/mycg sock_ops pinned /sys/fs/bpf/decoder
rm /sys/fs/bpf/decoder
bpftool prog load decoder.o /sys/fs/bpf/decoder type sockops
bpftool cgroup attach /sys/fs/cgroup/mycg sock_ops pinned /sys/fs/bpf/decoder multi
