#include "definitions.h"

#define bpf_print(fmt, ...)                                                   \
    do {                                                                      \
        static const char _fmt[] = "server - " fmt;                            \
        bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__);                  \
    } while (0)

#define bpf_print(fmt, ...)


static __always_inline int get_server_id(__be16 port)
{
    const __u16 ports[] = {TRACE_PORTS};

#pragma unroll
    for (int i = 0; i < sizeof(ports) / sizeof(ports[0]); i++)
    {
        if (port == ports[i])
        {
            return i;
        }
    }
    return -1;
}

#define TCPHDR_SYN 0x02

SEC("sockops_server")
int bpf_sockops_server(struct bpf_sock_ops* skops)
{
    int server_id = get_server_id(skops->local_port);
    if (server_id == -1)
    {
        return 1;
    }
    // if (3 <= skops->op && skops->op <= 5)
    bpf_print("skops->op %s", op_name(skops->op));
    bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);

    bpf_print("daddr = %u", bpf_ntohl(skops->remote_ip4));
    bpf_print("saddr = %u", bpf_ntohl(skops->local_ip4));
    bpf_print("dport = %u", bpf_ntohs(bpf_htons(bpf_htonl(skops->remote_port))));
    bpf_print("sport = %u", bpf_ntohs(bpf_htons(skops->local_port)));
    __u64 pidtig = bpf_get_current_pid_tgid();
    bpf_print("pidtig = %llu", pidtig);
    bpf_print("syn = %llu", skops->skb_tcp_flags & TCPHDR_SYN);

    switch (skops->op)
    {
    case BPF_SOCK_OPS_RWND_INIT:
        {
            // const struct ipv4_key key = {
            //     .daddr = skops->remote_ip4,
            //     .saddr = skops->local_ip4,
            //     .dport = bpf_htons(bpf_htonl(skops->remote_port)),
            //     .sport = bpf_htons(skops->local_port),
            // };
            // struct tcp_extension tcp_extension = {
            //     .connection_id = bpf_get_prandom_u32()
            // };
            // bpf_map_update_elem(&tcp_extension_egress_map, &key, &tcp_extension, BPF_ANY);
            break;
        }
    case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
        skops->reply = sizeof(struct tcp_extension_hdr);
        const long res = bpf_reserve_hdr_opt(skops, sizeof(struct tcp_extension_hdr), 0);
        if (res != 0)
        {
            bpf_print("bpf_reserve_hdr_opt %d", res);
        }
        break;
    case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
        {
            if (skops->family != AF_INET)
            {
                break;
            }
            // __u64 pidtig = bpf_get_current_pid_tgid();
            // bpf_print("%llu", pidtig);
            // __u32* connection_id = bpf_map_lookup_elem(&pid_to_connid, &pidtig);
            // if (connection_id == NULL)
            // {
            //     bpf_print("not found %llu", pidtig);
            //     return 0;
            // }
            if (skops->skb_tcp_flags & TCPHDR_SYN)
            {
                __u64 connection_id = bpf_get_prandom_u32();

                struct tcp_extension_hdr opt = {
                    .kind = TCPE_KIND,
                    .len = 8,
                    .magic = TCPE_MAGIC,
                    .connection_id = bpf_htonl(connection_id),
                };

                if (bpf_store_hdr_opt(skops, &opt, sizeof(opt), 0) != 0)
                {
                    bpf_print("bpf_store_hdr_opt failed");
                    break;
                }
            }
            // else
            // {
            // const struct ipv4_key key = {
            //     .daddr = skops->remote_ip4,
            //     .saddr = skops->local_ip4,
            //     .dport = bpf_htons(bpf_htonl(skops->remote_port)),
            //     .sport = bpf_htons(skops->local_port),
            // };
            // struct tcp_extension* ext = bpf_map_lookup_elem(&tcp_extension_egress_map, &key);
            // if (!ext)
            // {
            //     break;
            // }
            //
            // connection_id = ext->connection_id;
            // }

            break;
        }
    }
    return 1;
}

char __license[] SEC("license") = "GPL";
