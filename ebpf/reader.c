/**
 * Reader tc ebpf program on ingress
 * reads and stores all info related to TCPE
 */

#include "definitions.h"

#ifdef IS_SERVER
#define PREFIX "reader server - "
#else
#define PREFIX "reader client - "
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

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ipv4_key);
    __type(value, struct tcpe);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 4096);
} tcpe_conn_map SEC(".maps");


struct path_key
{
    struct ipv4_key ipv4;
    int index;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct path_key);
    __type(value, struct tcpe_path);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 4096);
} tcpe_path_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1); /* just one slot ⇒ acts like a global */
    __type(key, __u32);
    __type(value, __u64);
} global SEC(".maps");

int __always_inline increment_counter_and_return()
{
    __u32 k = 0;
    __u64* v = bpf_map_lookup_elem(&global, &k);
    if (v)
    {
        return __sync_fetch_and_add(v, 1);
    }
    __u32 zero = 0;
    if (bpf_map_update_elem(&global, &k, &zero, BPF_NOEXIST) != 0)
    {
        v = bpf_map_lookup_elem(&global, &k);
        if (v)
        {
            return __sync_fetch_and_add(v, 1);
        }
        bpf_print("unreachable");
    }
    return 0;
}


static __always_inline int get_app_id(__be16 port)
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

struct ipv4_key __always_inline get_key_client(const struct iphdr* iph, const struct tcphdr* tcp)
{
    const struct ipv4_key key = {
        .server_addr = iph->saddr,
        .client_addr = iph->daddr,
        .server_port = tcp->source,
        .client_port = tcp->dest,
    };
    return key;
}

struct ipv4_key __always_inline get_key_server(const struct iphdr* iph, const struct tcphdr* tcp)
{
    const struct ipv4_key key = {
        .server_addr = iph->daddr,
        .client_addr = iph->saddr,
        .server_port = tcp->dest,
        .client_port = tcp->source,
    };
    return key;
}

struct ipv4_key __always_inline get_key(const struct iphdr* iph, const struct tcphdr* tcp)
{
#ifdef IS_SERVER
    return get_key_server(iph, tcp);
#else
    return get_key_client(iph, tcp);
#endif
}

void __always_inline handle_initiation(struct iphdr* iph, struct tcphdr* tcp, __u32 connection_id)
{
    const struct ipv4_key key = get_key(iph, tcp);
    const struct tcpe value = {
        .connection_id = connection_id
    };
    bpf_map_update_elem(&tcpe_conn_map, &key, &value, BPF_ANY);
}

void __always_inline handle_new_path(
    struct iphdr* iph,
    struct tcphdr* tcp,
    __u32 address,
    __u16 port,
    __u8 priority,
    __u8 create
)
{
    bpf_print("create %u", create);
    const struct ipv4_key key = get_key(iph, tcp);
    const int index = increment_counter_and_return();
    const struct path_key pkey = {
        .ipv4 = key,
        .index = index,
    };
    const struct tcpe_path value = {
        .address = address,
        .port = port,
        .priority = priority,
        .create = create,
    };
    bpf_map_update_elem(&tcpe_path_map, &pkey, &value, BPF_ANY);
}

void __always_inline traverse_tcp_options(struct iphdr* iph, struct tcphdr* tcp, int opt_len, __u8 opts[40])
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
            /* option must be at least 4 bytes: kind, len, magic(2) */
            if (i + 4 > opt_len)
            {
                bpf_print("short TCPE option");
                return;
            }
            bpf_print("TCPE option");

            __u16 magic = (opts[(i + 3)] << 8) | opts[i + 2];
            if (
                (magic == TCPE_INITIAL && sizeof(struct tcpe_initial) > opt_len) ||
                (magic == TCPE_NEW_PATH && sizeof(struct tcpe_new_path) > opt_len)
            )
            {
                bpf_print("error loading TCPE option");
                return;
            }

            if (magic == TCPE_INITIAL)
            {
                __u32 connection_id = (opts[(i + 7)] << 24)
                    | (opts[(i + 6)] << 16)
                    | (opts[i + 5] << 8)
                    | opts[i + 4];
                connection_id = bpf_ntohl(connection_id);
                bpf_print("connection id %u", connection_id);
                handle_initiation(iph, tcp, connection_id);
                return;
            }
            if (magic == TCPE_NEW_PATH)
            {
                __u32 address = (opts[(i + 7)] << 24)
                    | (opts[(i + 6)] << 16)
                    | (opts[i + 5] << 8)
                    | opts[i + 4];
                __u16 port = (opts[i + 9] << 8) | (opts[i + 8]);
                __u8 priority = (opts[i + 10] >> 4);
                __u8 create = (opts[i + 10] & 0x08) != 0;
                bpf_print(" opts[i + 10] %u", opts[i + 10]);

                handle_new_path(iph, tcp, address, port, priority, create);
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
#ifdef IS_SERVER
    const int app_id = get_app_id(tcp->dest);
#else
    const int app_id = get_app_id(tcp->source);
#endif
    if (app_id < 0)
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
    if (tcp->fin || tcp->rst)
    {
        const struct ipv4_key key = get_key(iph, tcp);
        if (bpf_map_delete_elem(&tcpe_conn_map, &key) != 0)
        {
            bpf_print("error deleting connection id from tcpe_conn_map");
        }
    }

    __u8 opts[40];
    if (bpf_skb_load_bytes(skb, (__u32)((__u8*)opt - (__u8*)data),
                           opts, opt_len))
    {
        bpf_print("error loading TCP options");
        return TC_ACT_OK;
    }

    traverse_tcp_options(iph, tcp, opt_len, opts);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
