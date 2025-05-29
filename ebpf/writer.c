/**
 * Writer sockops ebpf program on egress
 * writes requested info on TCPE packets
 */

#include "definitions.h"

#ifdef IS_SERVER
#define PREFIX "server - "
#else
#define PREFIX "client - "
#endif

#ifdef DEBUG_CODE
#define bpf_print(fmt, ...)                                                   \
    do {                                                                      \
        static const char _fmt[] = PREFIX fmt;                                \
        bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__);                  \
    } while (0)
#else
#define bpf_print(fmt, ...)
#endif

static __always_inline int get_app_id(__be16 port)
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

#define TCPHDR_FIN 0x01
#define TCPHDR_SYN 0x02
#define TCPHDR_RST 0x04
#define TCPHDR_PSH 0x08
#define TCPHDR_ACK 0x10
#define TCPHDR_URG 0x20
#define TCPHDR_ECE 0x40
#define TCPHDR_CWR 0x80

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ipv4_key);
    __type(value, struct tcpe);
    __uint(max_entries, 4096);
} tcpe_conn_map SEC(".maps");


struct ipv4_key __always_inline get_key_client(struct bpf_sock_ops* skops)
{
    const struct ipv4_key key = {
        .server_addr = skops->remote_ip4,
        .client_addr = skops->local_ip4,
        .server_port = skops->remote_port >> 16,
        .client_port = (bpf_htonl(skops->local_port)) >> 16,
    };
    return key;
}

struct ipv4_key __always_inline get_key_server(struct bpf_sock_ops* skops)
{
    const struct ipv4_key key = {
        .server_addr = skops->local_ip4,
        .client_addr = skops->remote_ip4,
        .server_port = (bpf_htonl(skops->local_port)) >> 16,
        .client_port = skops->remote_port >> 16,
    };
    return key;
}


struct ipv4_key __always_inline get_key(struct bpf_sock_ops* skops)
{
#ifdef IS_SERVER
    return get_key_server(skops);
#else
    return get_key_client(skops);
#endif
}

SEC("sockops")
int bpf_sockops(struct bpf_sock_ops* skops)
{
#ifdef IS_SERVER
    __be16 app_port = skops->local_port;
#else
    __be16 app_port = bpf_htonl(skops->remote_port);
#endif

    const int app_id = get_app_id(app_port);
    if (app_id == -1 || skops->family != AF_INET)
    {
        return 1;
    }

    __u64 pid_tig = bpf_get_current_pid_tgid();
    bpf_print("skops->op %s, pid %u, syn %u", op_name(skops->op), pid_tig >> 32, skops->skb_tcp_flags & TCPHDR_SYN);
    long ret = bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
    if (ret != 0)
    {
        bpf_print("bpf_sock_ops_cb_flags_set %u", ret);
    }

    int size = -1;
    switch (skops->op)
    {
    case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
        ret = bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
        if (ret != 0)
        {
            bpf_print("bpf_sock_ops_cb_flags_set %u", bpf_sock_ops_cb_flags_set);
        }

        if (skops->skb_tcp_flags & TCPHDR_SYN)
        {
            size = sizeof(struct tcpe_initial);
        }

        if (size != -1)
        {
            bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
            skops->reply = size;
            ret = bpf_reserve_hdr_opt(skops, size, 0);
            if (ret != 0)
            {
                bpf_print("bpf_reserve_hdr_opt %d", ret);
            }
        }
        break;
    case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
        {
            const struct ipv4_key key = get_key(skops);
            if (skops->skb_tcp_flags & TCPHDR_SYN)
            {
                __u32 connection_id;
                __u32* existing_connection = bpf_map_lookup_elem(&tcpe_conn_map, &key);
                if (existing_connection != NULL)
                {
                    bpf_print("existing_connection");
                    connection_id = *existing_connection;
                }
                else
                {
                    bpf_print("not existing_connection");
                    connection_id = bpf_get_prandom_u32();
                }
                bpf_print("connection_id = %u", connection_id);

                const struct tcpe_initial opt = {
                    .kind = TCPE_KIND,
                    .len = 8,
                    .magic = TCPE_INITIAL,
                    .connection_id = bpf_htonl(connection_id),
                };

                if (bpf_store_hdr_opt(skops, &opt, sizeof(opt), 0) != 0)
                {
                    bpf_print("bpf_store_hdr_opt failed");
                    break;
                }
            }

            break;
        }
    }
    return 1;
}

char __license[] SEC("license") = "GPL";
