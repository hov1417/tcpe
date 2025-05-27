#pragma once

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
#include <asm-generic/errno.h>
#include <linux/bpf.h>
#include <linux/filter.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define AF_INET		2


#define TCPE_KIND 254
#define TCPE_INITIAL bpf_htons(1417)
#define TCPE_NEW_PATH bpf_htons(1418)

struct tcpe
{
    __u32 connection_id;
};

struct tcpe_path
{
    __u32 address;
    __u16 port;
};

struct __attribute__((__packed__)) tcpe_initial
{
    __u8 kind; /* 254 */
    __u8 len; /* 8   */
    __u16 magic; /* 1417 */
    __u32 connection_id;
};

struct __attribute__((__packed__)) tcpe_new_path
{
    __u8 kind; /* 254 */
    __u8 len; /* 8 */
    __u16 magic; /* 1418 */
    __u32 address;
    __u16 port;
    __u16 padd;
};

struct __attribute__((__packed__)) ipv4_key
{
    __u32 server_addr;
    __u32 client_addr;
    __u16 server_port;
    __u16 client_port;
};

inline char* op_name(const int op)
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
    default:
        return "UNKNOWN";
    }
}
