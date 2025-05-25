clang -O2 -g -Wall -target bpf -c server.c -o server.o -DTRACE_PORTS=8080 -DDEBUG_CODE
bpftool cgroup detach /sys/fs/cgroup/server sock_ops pinned /sys/fs/bpf/server
rm /sys/fs/bpf/server
bpftool prog load server.o /sys/fs/bpf/server type sockops
bpftool cgroup attach /sys/fs/cgroup/server sock_ops pinned /sys/fs/bpf/server multi
