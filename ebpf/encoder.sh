clang -O2 -g -target bpf -c encoder.c -o encoder.o -DTRACE_PORTS=8080
rm /sys/fs/bpf/myopt || 1
bpftool prog load encoder.o /sys/fs/bpf/myopt type sockops
bpftool cgroup detach /sys/fs/cgroup/mycg sock_ops pinned /sys/fs/bpf/myopt || 1
bpftool cgroup attach /sys/fs/cgroup/mycg sock_ops pinned /sys/fs/bpf/myopt
