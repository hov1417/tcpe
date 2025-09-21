#!/usr/bin/env bash

sudo rm -f /sys/fs/bpf/tc/globals/tcpe_conn_map \
           /sys/fs/bpf/tc/globals/connection_ids \
           /sys/fs/bpf/tc/globals/tcpe_path_map \
           /sys/fs/bpf/tc/globals/server_rodata \
           /sys/fs/bpf/tc/globals/_rodata_str1_1 \
           /sys/fs/bpf/tcpe_conn_map \
           /sys/fs/bpf/connection_ids \
           /sys/fs/bpf/tcpe_path_map

clang -O2 -g -Wall -target bpf -c writer.c -o server.o -DTRACE_PORTS=8080,8081,8082 -DIS_SERVER -DDEBUG_CODE
bpftool cgroup detach /sys/fs/cgroup/server sock_ops pinned /sys/fs/bpf/server
rm -f /sys/fs/bpf/server
bpftool prog load server.o /sys/fs/bpf/server type sockops pinmaps /sys/fs/bpf/tc/globals
bpftool cgroup attach /sys/fs/cgroup/server sock_ops pinned /sys/fs/bpf/server multi

DEVICE=${1-wlp59s0}
tc filter del dev $DEVICE ingress
tc qdisc del dev $DEVICE clsact

clang -g -O2 -Wall -target bpf -c reader.c -o reader-server.o -DTRACE_PORTS=8080,8081,8082 -DIS_SERVER -DDEBUG_CODE

tc qdisc add dev $DEVICE clsact
tc filter add dev $DEVICE ingress bpf da obj reader-server.o sec reader_ingress