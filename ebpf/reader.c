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

void __always_inline traverse_tcp_options(int opt_len, __u8 opts[40])
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
            long magic_idx = i + 3;
            if (magic_idx >= opt_len)
            {
                bpf_print("error loading TCPE Magic");
                return;
            }
            __u16 magic = (opts[magic_idx] << 8) | opts[magic_idx - 1];
            if (magic == TCPE_MAGIC)
            {
                long cn_idx = i + 7;
                if (cn_idx >= opt_len)
                {
                    bpf_print("error loading TCPE connection id");
                    return;
                }
                __u32 connection_id = (opts[magic_idx] << 24)
                    | (opts[magic_idx] << 16)
                    | (opts[magic_idx - 2] << 8)
                    | opts[magic_idx - 3];
                bpf_print("connection id %u", connection_id);
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

    traverse_tcp_options(opt_len, opts);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
