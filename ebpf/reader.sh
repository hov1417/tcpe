#tc filter del dev wlp59s0 ingress
#tc qdisc del dev wlp59s0 clsact
#
#clang -g -O2 -Wall -target bpf -c reader.c -o reader.o -DTRACE_PORTS=8080 -DDEBUG_CODE
#
#tc qdisc add dev wlp59s0 clsact
#tc filter add dev wlp59s0 ingress bpf da obj reader.o sec reader_ingress

tc filter del dev lo ingress
tc qdisc del dev lo clsact

clang -g -O2 -Wall -target bpf -c reader.c -o reader.o -DTRACE_PORTS=8080 -DDEBUG_CODE

tc qdisc add dev lo clsact
tc filter add dev lo ingress bpf da obj reader.o sec reader_ingress
