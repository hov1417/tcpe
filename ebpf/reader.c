#include "definitions.h"
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

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ipv4_key);
    __type(value, struct tcpe);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 4096);
} tcpe_conn_map SEC(".maps");


#ifdef DEBUG_CODE
#define bpf_print(fmt, ...)                                                   \
    do {                                                                      \
        static const char _fmt[] = "reader - " fmt;                                       \
        bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__);                  \
    } while (0)
#else
#define bpf_print(fmt, ...)
#endif

static __always_inline int get_server_id(__be16 port)
{
    const __u16 ports[] = {TRACE_PORTS};

#pragma unroll
    for (int i = 0; i < sizeof(ports) / sizeof(ports[0]); i++)
    {
        __u16 dst_port = bpf_htons(ports[i]);
        if (port == dst_port)
        {
            return i;
        }
    }
    return -1;
}

void __always_inline traverse_tcp_options(int opt_len, __u8 opts[40], __u32* connection_id_ret)
{
    __u32 next_kind = 0;
    for (int i = 0; i < opt_len; i++)
    {
        if (i != next_kind)
            continue;
        __u8 kind = opts[i];
        if (kind == 0)
            break;

        if (kind == 1)
        {
            next_kind = i + 1;
            continue;
        }

        if (i + 1 >= opt_len)
            break;

        __u8 len = opts[i + 1];

        if (opt_len < i + len || len < 2)
            break;
        if (kind == TCPE_KIND)
        {
            /* option must be at least 8 bytes: kind, len, magic(2), id(4) */
            if (i + 8 > opt_len)
            {
                bpf_print("error loading TCPE option");
                return;
            }

            __u16 magic = (opts[(i + 3)] << 8) | opts[i + 2];
            if (magic == TCPE_MAGIC)
            {
                __u32 connection_id = (opts[(i + 7)] << 24)
                    | (opts[(i + 6)] << 16)
                    | (opts[i + 5] << 8)
                    | opts[i + 4];
                *connection_id_ret = bpf_ntohl(connection_id);
                bpf_print("connection id %u", *connection_id_ret);
                return;
            }
        }
        next_kind = i + len;
    }
}

SEC("reader_ingress")
int reader_ingress_func(struct __sk_buff* skb)
{
    struct ethhdr* eth = (void*)(long)skb->data;
    long ip_ptr = (long)eth + sizeof(struct ethhdr);
    if (ip_ptr + sizeof(struct iphdr) >= skb->data_end)
    {
        return TC_ACT_OK;
    }
    struct iphdr* iph = (void*)ip_ptr;
    if (iph->protocol != IPPROTO_TCP || iph->version != 4)
    {
        return TC_ACT_OK;
    }

    long tcp_ptr = (long)iph + (iph->ihl << 2);
    if (tcp_ptr >= skb->data_end)
    {
        return TC_ACT_OK;
    }
    struct tcphdr* tcp = (void*)tcp_ptr;
    if ((long)tcp + sizeof(struct tcphdr) >= skb->data_end)
    {
        return TC_ACT_OK;
    }
    const int server_id = get_server_id(tcp->source);
    if (server_id < 0)
    {
        return TC_ACT_OK;
    }

    void* data = (void*)(long)skb->data;
    void* opt = (void*)tcp + sizeof(struct tcphdr);

    __u32 hdr_len = tcp->doff << 2;
    int opt_len = hdr_len - sizeof(struct tcphdr);
    if (opt_len <= 0)
    {
        bpf_print("no header options");
        return TC_ACT_OK;
    }

    __u8 opts[40];
    if (bpf_skb_load_bytes(skb, (__u32)((__u8*)opt - (__u8*)data),
                           opts, opt_len))
    {
        bpf_print("error loading TCP options");
        return TC_ACT_OK;
    }

    __u32 connection_id = 0;
    traverse_tcp_options(opt_len, opts, &connection_id);
    if (connection_id != 0)
    {
        // client side keys are in reverse order
        const struct ipv4_key key = {
            .daddr = iph->saddr,
            .saddr = iph->daddr,
            .dport = tcp->source,
            .sport = tcp->dest,
        };
        const struct tcpe value = {
            .connection_id = connection_id
        };
        bpf_map_update_elem(&tcpe_conn_map, &key, &value, BPF_ANY);
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
