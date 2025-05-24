#include "definitions.h"


#define bpf_print(fmt, ...)                                                   \
    do {                                                                      \
        static const char _fmt[] = "client - " fmt;                            \
        bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__);                  \
    } while (0)

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

SEC("sockops_client")
int bpf_sockops_client(struct bpf_sock_ops* skops)
{
    int server_id = get_server_id(bpf_htonl(skops->remote_port));
    if (server_id == -1 || skops->family != AF_INET)
    {
        return 1;
    }
    bpf_print("skops->op %s", op_name(skops->op));
    bpf_sock_ops_cb_flags_set(
        skops,
        BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG | BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG
    );
    struct tcp_extension_hdr hdr = {
        .kind = 254,
        .len = 4, // search query size, not header size
        .magic = bpf_htons(1417),
        .connection_id = 0,
    };
    long ret = bpf_load_hdr_opt(skops, &hdr, sizeof(hdr), 0);
    // Not Found
    if (ret == -ENOMSG)
    {
        bpf_print("not found");
        return 1;
    }
    if (ret < 0)
    {
        bpf_printk("bpf_load_hdr_opt %d", ret);
        return 0;
    }

    switch (skops->op)
    {
    case BPF_SOCK_OPS_PARSE_HDR_OPT_CB:
        {
            struct tcp_extension_hdr hdr = {
                .kind = 254,
                .len = 4, // search query size, not header size
                .magic = bpf_htons(1417),
                .connection_id = 0,
            };
            int ret = bpf_load_hdr_opt(skops, &hdr, sizeof(hdr), 0);
            // Not Found
            if (ret == -ENOMSG)
            {
                return 1;
            }
            if (ret < 0)
            {
                bpf_printk("bpf_load_hdr_opt %d", ret);
                return 0;
            }

            struct ipv4_key key = {
                .daddr = skops->remote_ip4,
                .saddr = skops->local_ip4,
                .dport = bpf_htons(bpf_htonl(skops->remote_port)),
                .sport = bpf_htons(skops->local_port),
            };
            struct tcpe tcp_extension = {
                .connection_id = bpf_ntohl(hdr.connection_id),
            };
            if (bpf_map_update_elem(&tcp_extension_ingress_map, &key, &tcp_extension, BPF_ANY) < 0)
            {
                bpf_print("Error setting ingress value");
                return 1;
            }
            break;
        }
    }
    return 1;
}

char __license[] SEC("license") = "GPL";
