tc filter del dev wlp59s0 ingress
tc qdisc del dev wlp59s0 clsact

clang -g -O2 -Wall -target bpf -c reader.c -o reader.o -DTRACE_PORTS=8080 -DLB_ADDR="$(./ipv4toi.py 192.168.2.79)" -DLB_PORT=9000\
        -DHACK_FOR_SUBNETS=1 #-DDEBUG_CODE

tc qdisc add dev wlp59s0 clsact
tc filter add dev wlp59s0 ingress bpf da obj reader.o sec reader_ingress
