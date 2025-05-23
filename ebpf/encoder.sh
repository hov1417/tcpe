clang -O2 -g -target bpf -c encoder.c -o encoder.o -DTRACE_PORTS=8080
bpftool cgroup detach /sys/fs/cgroup/mycg sock_ops pinned /sys/fs/bpf/encoder
rm /sys/fs/bpf/encoder
bpftool prog load encoder.o /sys/fs/bpf/encoder type sockops
bpftool cgroup attach /sys/fs/cgroup/mycg sock_ops pinned /sys/fs/bpf/encoder multi
