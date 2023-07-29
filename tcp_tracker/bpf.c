#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <linux/pkt_cls.h>



struct key_t {
    
    unsigned int valid;
    unsigned int src_ip; unsigned int src_port;
    unsigned int dst_ip; unsigned int dst_port;
};
struct stat_t {
    unsigned long bts; // Bits/Bytes
    unsigned long pkt; // Packets  
};

BPF_HASH(session_data, struct key_t, struct stat_t, 256);

static __always_inline void *move_on
    (void *pointer, unsigned char offset);
static __always_inline int   is_okay
    (void *pointer, unsigned char offset, void *end);
static __always_inline int   is_ipv4
    (unsigned short protocol);
static __always_inline int   is_tcp
    (unsigned char protocol);
static __always_inline void  get_connection_key
    (void * data, void * data_end, struct key_t * key);

int trace_tcp_connections (struct __sk_buff * ctx) {

    struct key_t key = {
        .valid    = 0U,
        .src_ip   = 0U,
        .dst_ip   = 0U,
        .src_port = 0U,
        .dst_port = 0U,
    };
    get_connection_key((void *)(long)ctx->data, (void *)(long)ctx->data_end, &key);
    if(!key.valid) 
        return TC_ACT_OK;

    struct stat_t   new_value = {.bts = 0LU, .pkt = 0LU};
    struct stat_t * prv_value = session_data.lookup_or_try_init(&key, &new_value);

    if(!prv_value) 
        return TC_ACT_OK;
    __sync_fetch_and_add(&prv_value->pkt, 1);
    __sync_fetch_and_add(&prv_value->bts, ctx->len);
    return TC_ACT_OK;
}



static __always_inline void *move_on
    (void *pointer, unsigned char offset) {
    return pointer + offset;
}
static __always_inline int   is_okay
    (void *pointer, unsigned char offset, void *end) {
    if (pointer + offset <= end)
        return 1; // True
    return 0;     // False
}
static __always_inline int   is_ipv4
    (unsigned short protocol) {
    unsigned short ipv4_protocol = 0x0800;
    if (protocol == ipv4_protocol)
        return 1; // True
    return 0;     // False
}
static __always_inline int   is_tcp
    (unsigned char protocol) {
    unsigned char tcp_protocol = 0x06;
    if (protocol == tcp_protocol)
        return 1; // True
    return 0;     // False
}
static __always_inline void  get_connection_key
    (void * data, void * data_end, struct key_t * key) {

    struct ethhdr *ethernet;
    struct iphdr  *ip;
    struct tcphdr *tcp;

    if (is_okay(data, sizeof(struct ethhdr), data_end) == 0) {
        return;
    }
    ethernet = (struct ethhdr *) data;
    if (is_ipv4(__constant_htons(ethernet->h_proto)) == 0) {
        return;
    }
    data = move_on(data, sizeof(struct ethhdr));
    if (is_okay(data, sizeof(struct iphdr), data_end) == 0) {
        return;
    }
    ip = (struct iphdr *) data;
    if (is_tcp(ip->protocol) == 0x00) {
        return;
    }
    data = move_on(data, sizeof(struct tcphdr));
    if (is_okay(data, sizeof(struct tcphdr), data_end) == 0) {
        return;
    }
    tcp = (struct tcphdr *) data;
    key->valid    = 1U;
    key->src_ip   = (unsigned int)__constant_ntohl(ip->saddr);
    key->dst_ip   = (unsigned int)__constant_ntohl(ip->daddr);
    key->src_port = (unsigned int)__constant_ntohs(tcp->source);
    key->dst_port = (unsigned int)__constant_ntohs(tcp->dest);
    return;
}