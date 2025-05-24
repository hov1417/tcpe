#include "../definitions.h"

// #ifdef DEBUG_CODE
#define bpf_print(fmt, ...)                                                   \
    do {                                                                      \
        static const char _fmt[] = "reader - " fmt;                                       \
        bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__);                  \
    } while (0)
// #endif
// #ifndef DEBUG_CODE
// #define bpf_print(fmt, ...)
// #endif

static __always_inline int get_server_id(__be16 port)
{
    const __u16 ports[2] = {TRACE_PORTS};

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

    __u32 tcp_header_options_ptr = (long)tcp + sizeof(struct tcphdr);
    __u32 data_offset = tcp->doff * 4;
    if (data_offset >= skb->data_end)
    {
        return TC_ACT_OK;
    }
    while (tcp_header_options_ptr < skb->data_end)
    {
        __u8 kind = *(__u8*)tcp_header_options_ptr;
        if (kind == 0 || kind == 1)
        {
            // tcp_header_options_ptr += 1;
        }
        else if (kind == TCPE_KIND)
        {
            if (tcp_header_options_ptr + 3 >= skb->data_end)
            {
                return TC_ACT_OK;
            }
            __u16 magic = *(__u16*)(tcp_header_options_ptr + 2);
            if (magic == TCPE_MAGIC)
            {
                if (tcp_header_options_ptr + 7 >= skb->data_end)
                {
                    return TC_ACT_OK;
                }
                __u32 connection_id = *(__u32*)(tcp_header_options_ptr + 4);
                bpf_print("connection id %u", connection_id);
                return TC_ACT_OK;
            }
        }
        if (tcp_header_options_ptr + 1 >= skb->data_end)
        {
            return TC_ACT_OK;
        }
        __u8 len = *(__u8*)(tcp_header_options_ptr + 1);
        if (len == 0)
        {
            return TC_ACT_OK;
        }
        tcp_header_options_ptr += len - 1;
    }
    {



        // if (tcp_header_options_ptr > data_offset)
        // {
        //     break;
        // }
    }
    //
    // // reverse order for egress
    // const struct ipv4_key key = {
    //     .daddr = iph->saddr,
    //     .saddr = iph->daddr,
    //     .dport = tcp->source,
    //     .sport = tcp->dest,
    // };
    //
    // if (check_fin_egress(server_id, &key, tcp) != 0)
    // {
    //     bpf_print("error while check_fin_egress");
    //     return TC_ACT_SHOT;
    // }
    // // if when removing availability request succeeds
    // // then we should add availability and not use dsr
    // if (bpf_map_delete_elem(&ipv4_availability_req, &key) == 0)
    // {
    //     if (set_availability_opt4(skb, iph, server_id) != 0)
    //     {
    //         bpf_print("error while availability_set_opt4");
    //     }
    //     return TC_ACT_OK;
    // }
    //
    // struct ipv4_dsr_info_value* dsr_entry = bpf_map_lookup_elem(&ipv4_dsr_info, &key);
    // if (dsr_entry != NULL)
    // {
    //     if (dsr_replace(dsr_entry, skb, eth, iph, tcp) != 0)
    //     {
    //         bpf_print("error replacing with dsr value");
    //     }
    //     return TC_ACT_OK;
    // }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
