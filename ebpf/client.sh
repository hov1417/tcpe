clang -O2 -g -Wall -target bpf -c client.c -o client.o -DTRACE_PORTS=8080
bpftool cgroup detach /sys/fs/cgroup/client sock_ops pinned /sys/fs/bpf/client
rm /sys/fs/bpf/client
bpftool prog load client.o /sys/fs/bpf/client type sockops
bpftool cgroup attach /sys/fs/cgroup/client sock_ops pinned /sys/fs/bpf/client multi
