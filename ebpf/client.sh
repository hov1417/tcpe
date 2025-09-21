#!/usr/bin/env bash

sudo rm -f /sys/fs/bpf/tc/globals/tcpe_conn_map \
           /sys/fs/bpf/tc/globals/connection_ids \
           /sys/fs/bpf/tc/globals/tcpe_path_map \
           /sys/fs/bpf/tc/globals/client_rodata \
           /sys/fs/bpf/tc/globals/_rodata_str1_1 \
           /sys/fs/bpf/tcpe_conn_map \
           /sys/fs/bpf/connection_ids \
           /sys/fs/bpf/tcpe_path_map

clang -O2 -g -Wall -target bpf -c writer.c -o client.o -DTRACE_PORTS=8080,8081,8082 -DDEBUG_CODE
bpftool cgroup detach /sys/fs/cgroup/client sock_ops pinned /sys/fs/bpf/client
rm -f /sys/fs/bpf/client
bpftool prog load client.o /sys/fs/bpf/client type sockops pinmaps /sys/fs/bpf/tc/globals
bpftool cgroup attach /sys/fs/cgroup/client sock_ops pinned /sys/fs/bpf/client multi

DEVICE=${1-wlp59s0}
tc filter del dev $DEVICE ingress
tc qdisc del dev $DEVICE clsact

clang -g -O2 -Wall -target bpf -c reader.c -o reader-client.o -DTRACE_PORTS=8080,8081,8082 -DDEBUG_CODE

tc qdisc add dev $DEVICE clsact
tc filter add dev $DEVICE ingress bpf da obj reader-client.o sec reader_ingress

