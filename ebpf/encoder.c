#include <linux/bpf.h>
#include <linux/filter.h>
#include <sys/socket.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#define bpf_print(fmt, ...)                                                   \
    do {                                                                      \
        static const char _fmt[] = fmt;                                       \
        bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__);                  \
    } while (0)


struct tcp_extension
{
    __u32 connection_id;
};

struct __attribute__((__packed__)) tcp_extension_hdr
{
    __u8 kind; /* 254 */
    __u8 len; /* 8   */
    __u32 connection_id;
    __u16 pad;
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
    __type(value, struct tcp_extension);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 4096);
} tcp_extension_ingress_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ipv4_key);
    __type(value, struct tcp_extension);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 4096);
} tcp_extension_egress_map SEC(".maps");


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

SEC("sockops")
int bpf_sockops_handler(struct bpf_sock_ops* skops)
{
    int server_id = get_server_id(skops->local_port);
    if (server_id == -1)
    {
        return 1;
    }
    bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);

    switch (skops->op)
    {
    case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
        skops->reply = sizeof(struct tcp_extension_hdr);
        int res = bpf_reserve_hdr_opt(skops, sizeof(struct tcp_extension_hdr), 0);
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
            const struct ipv4_key key = {
                .daddr = skops->remote_ip4,
                .saddr = skops->local_ip4,
                .dport = bpf_htons(bpf_htonl(skops->remote_port)),
                .sport = bpf_htons(skops->local_port),
            };
            struct tcp_extension* ext = bpf_map_lookup_elem(&tcp_extension_egress_map, &key);
            if (!ext)
            {
                break;
            }

            struct tcp_extension_hdr opt = {
                .kind = 254,
                .len = 8,
                .connection_id = bpf_htonl(ext->connection_id),
                .pad = 0,
            };
            if (bpf_store_hdr_opt(skops, &opt, sizeof(opt), 0) != 0)
            {
                bpf_print("bpf_store_hdr_opt failed");
            }
            break;
        }
    }
    return 1;
}

char __license[] SEC("license") = "GPL";
