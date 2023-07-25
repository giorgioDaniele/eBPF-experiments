

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct key_t {

    // Layer 3
    unsigned int src_ip;
    unsigned int dst_ip;
    // Layer 4
    unsigned short src_port;
    unsigned short dst_port;
};

struct value_t{

    // Statistics
    unsigned long bytes;
    unsigned long packets;
    // Lock
    struct bpf_spin_lock lock;
};

BPF_HASH(connections, struct key_t, struct value_t, 256);

static __always_inline void *move_on(void *pointer, unsigned char offset) {
    return pointer + offset;
}
static __always_inline int is_okay(void *pointer, unsigned char offset, void *end) {
    if (pointer + offset <= end)
        return 1; // True
    return 0;     // False
}
static __always_inline int is_ipv4(unsigned short protocol) {
    unsigned short ipv4_protocol = 0x0800;
    if (protocol == ipv4_protocol)
        return 1; // True
    return 0;     // False
}
static __always_inline int is_tcp(unsigned char protocol) {
    unsigned char tcp_protocol = 0x06;
    if (protocol == tcp_protocol)
        return 1; // True
    return 0;     // False
}

static __always_inline struct key_t new_key(struct iphdr *ip, struct tcphdr *tcp) {
    struct key_t key = {
        .src_ip = __constant_ntohl(ip->saddr),
        .dst_ip = __constant_ntohl(ip->daddr),
        .src_port = __constant_ntohs(tcp->source),
        .dst_port = __constant_ntohs(tcp->dest)
    };
    return key;
}
static __always_inline struct value_t make_new_value() {

    struct bpf_spin_lock lock;
    struct value_t value = {
        .bytes   = 0,
        .packets = 0,
        .lock    = lock
    };
    return value;
}

int tcp_logger(struct xdp_md *ctx) {

    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    unsigned int size = (data_end - data);

    struct ethhdr *ethernet;
    struct iphdr *ip;
    struct tcphdr *tcp;

    if (is_okay(data, sizeof(struct ethhdr), data_end) == 0)
        return XDP_PASS;

    ethernet = (struct ethhdr *)data;
    if (is_ipv4(__constant_htons(ethernet->h_proto)) == 0)
        return XDP_PASS;

    data = move_on(data, sizeof(struct ethhdr));
    if (is_okay(data, sizeof(struct iphdr), data_end) == 0)
        return XDP_PASS;

    ip = (struct iphdr *)data;
    if (is_tcp(ip->protocol) == 0)
        return XDP_PASS;

    data = move_on(data, sizeof(struct tcphdr));
    if (is_okay(data, sizeof(struct tcphdr), data_end) == 0)
        return XDP_PASS;
    tcp = (struct tcphdr *)data;

    struct key_t      key    = new_key(ip, tcp);
    struct value_t new_value = make_new_value();

    struct value_t *value    = connections.lookup_or_try_init(&key, &new_value);

    if(value != NULL) {
        // Notice that my program is running on a multi-core system, so I do not 
        // care about the physical core which processes the packet, I just to make
        // my map consistent, by updating it synchronously. So, I use a spin lock
        bpf_spin_lock(&value->lock);
        value->bytes    = value->bytes   +  size;
        value->packets  = value->packets +  1;
        bpf_spin_unlock(&value->lock);
    }
    bpf_trace_printk("Done at %lu, size = %u!", bpf_ktime_get_ns(), size);

    return XDP_PASS;
}
