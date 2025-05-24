#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stddef.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <stdio.h>
#include <asm-generic/errno.h>
#include <sys/socket.h>
#include <linux/bpf.h>
#include <linux/filter.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TCPE_KIND 254
#define TCPE_MAGIC bpf_htons(1417)


struct tcpe
{
    __u32 connection_id;
};

struct __attribute__((__packed__)) tcp_extension_hdr
{
    __u8 kind; /* 254 */
    __u8 len; /* 8   */
    __u16 magic; /* 1417 */
    __u32 connection_id;
};

struct __attribute__((__packed__)) ipv4_key
{
    __u32 daddr;
    __u32 saddr;
    __u16 dport;
    __u16 sport;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ipv4_key);
    __type(value, struct tcpe);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 4096);
} tcp_extension_ingress_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ipv4_key);
    __type(value, struct tcpe);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 4096);
} tcpe_egress_map SEC(".maps");


// struct __attribute__((__packed__)) ipv4_key_3
// {
//     __u32 daddr;
//     __u32 saddr;
//     __u16 dport;
// };

// struct
// {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __type(key, struct ipv4_key_3);
//     __type(value, struct tcpe);
//     __uint(pinning, LIBBPF_PIN_BY_NAME);
//     __uint(max_entries, 4096);
// } tcpe_egress_map_3 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 4096);
} pid_to_connid SEC(".maps");

char* op_name(int op)
{
    switch (op)
    {
    case BPF_SOCK_OPS_VOID:
        return "BPF_SOCK_OPS_VOID";
    case BPF_SOCK_OPS_TIMEOUT_INIT:
        return "BPF_SOCK_OPS_TIMEOUT_INIT";
    case BPF_SOCK_OPS_RWND_INIT:
        return "BPF_SOCK_OPS_RWND_INIT";
    case BPF_SOCK_OPS_TCP_CONNECT_CB:
        return "BPF_SOCK_OPS_TCP_CONNECT_CB";
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        return "BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB";
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        return "BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB";
    case BPF_SOCK_OPS_NEEDS_ECN:
        return "BPF_SOCK_OPS_NEEDS_ECN";
    case BPF_SOCK_OPS_BASE_RTT:
        return "BPF_SOCK_OPS_BASE_RTT";
    case BPF_SOCK_OPS_RTO_CB:
        return "BPF_SOCK_OPS_RTO_CB";
    case BPF_SOCK_OPS_RETRANS_CB:
        return "BPF_SOCK_OPS_RETRANS_CB";
    case BPF_SOCK_OPS_STATE_CB:
        return "BPF_SOCK_OPS_STATE_CB";
    case BPF_SOCK_OPS_TCP_LISTEN_CB:
        return "BPF_SOCK_OPS_TCP_LISTEN_CB";
    case BPF_SOCK_OPS_RTT_CB:
        return "BPF_SOCK_OPS_RTT_CB";
    case BPF_SOCK_OPS_PARSE_HDR_OPT_CB:
        return "BPF_SOCK_OPS_PARSE_HDR_OPT_CB";
    case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
        return "BPF_SOCK_OPS_HDR_OPT_LEN_CB";
    case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
        return "BPF_SOCK_OPS_WRITE_HDR_OPT_CB";
    }
    return "";
}
