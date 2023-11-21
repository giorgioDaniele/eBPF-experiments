#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

struct tcp_snapshot_t {

    unsigned int  valid;
    unsigned int  srcip; unsigned int srcprt;
    unsigned int  dstip; unsigned int dstprt;

    unsigned int syn;
    unsigned int rst;
    unsigned int fin;
    unsigned int urg;
    unsigned int ack; 
    unsigned int psh;

};

struct icmp_snapshot_t {

    unsigned int  valid;
    unsigned int  srcip; unsigned int srcprt;
    unsigned int  dstip; unsigned int dstprt;

};

struct ipv4_snapshot_t {

    unsigned int  valid;
    unsigned int  srcip; unsigned int srcprt;
    unsigned int  dstip; unsigned int dstprt;  
};

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

static __always_inline int   is_icmp
    (unsigned char protocol) {
    unsigned char icmp_protocol = 0x01;
    if (protocol == icmp_protocol)
        return 1; // True
    return 0;     // False
}

static __always_inline void make_tcp_snapshot
    (void * data, void * data_end, struct tcp_snapshot_t * snapshot) {

    struct ethhdr *ethh;
    struct iphdr  *ip4h;
    struct tcphdr *tcph;

    if (!is_okay(data, sizeof(struct ethhdr), data_end)) {return;}

    ethh = (struct ethhdr *) data;
    if (!is_ipv4(__constant_htons(ethh->h_proto))) {return;}

    data = move_on(data, sizeof(struct ethhdr));
    if (!is_okay(data, sizeof(struct iphdr), data_end)) {return;}

    ip4h = (struct iphdr *) data;
    if (!is_tcp(ip4h->protocol)) {return;}

    data = move_on(data, sizeof(struct tcphdr));
    if (!is_okay(data, sizeof(struct tcphdr), data_end))  {return;}
    
    tcph = (struct tcphdr *) data;

    snapshot->valid    = 1U;

    snapshot->srcip  = (unsigned int)__constant_ntohl(ip4h->saddr);
    snapshot->dstip  = (unsigned int)__constant_ntohl(ip4h->daddr);
    snapshot->srcprt = (unsigned int)__constant_ntohs(tcph->source);
    snapshot->dstprt = (unsigned int)__constant_ntohs(tcph->dest);

    snapshot->ack = (unsigned int)tcph->ack;
    snapshot->syn = (unsigned int)tcph->syn;
    snapshot->urg = (unsigned int)tcph->urg;
    snapshot->fin = (unsigned int)tcph->fin;
    snapshot->rst = (unsigned int)tcph->rst;
    snapshot->psh = (unsigned int)tcph->psh;

    return;
}

static __always_inline void make_icmp_snapshot
    (void * data, void * data_end, struct icmp_snapshot_t * snapshot) {

    struct ethhdr *ethh;
    struct iphdr  *ip4h;

    if (!is_okay(data, sizeof(struct ethhdr), data_end)) {return;}

    ethh = (struct ethhdr *) data;
    if (!is_ipv4(__constant_htons(ethh->h_proto))) {return;}

    data = move_on(data, sizeof(struct ethhdr));   
    if (!is_okay(data, sizeof(struct iphdr), data_end))  {return;}

    ip4h = (struct iphdr *) data;
    if (!is_icmp(ip4h->protocol)) {return;}
    
    snapshot->valid = 1U;

    snapshot->srcip  = (unsigned int)__constant_ntohl(ip4h->saddr);
    snapshot->dstip  = (unsigned int)__constant_ntohl(ip4h->daddr);
 
    return;
}

static __always_inline void make_ipv4_snapshot
    (void * data, void * data_end, struct ipv4_snapshot_t * snapshot) {

    struct ethhdr *ethh;
    struct iphdr  *ip4h;

    if (!is_okay(data, sizeof(struct ethhdr), data_end)) {return;}

    ethh = (struct ethhdr *) data;
    if (!is_ipv4(__constant_htons(ethh->h_proto))) {return;}

    data = move_on(data, sizeof(struct ethhdr));   
    if (!is_okay(data, sizeof(struct iphdr), data_end))  {return;}

    ip4h = (struct iphdr *) data;
    
    snapshot->valid = 1U;

    snapshot->srcip  = (unsigned int)__constant_ntohl(ip4h->saddr);
    snapshot->dstip  = (unsigned int)__constant_ntohl(ip4h->daddr);
 
    return;
}

struct key_t {
    unsigned int  srcip; 
    unsigned int  srcprt;
    unsigned int  dstip; 
    unsigned int  dstprt;
};

struct value_t {
    unsigned long long timestamp;
    unsigned int       ifindex;
};

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,         struct key_t);
    __type(value,       struct value_t);
} fib SEC(".maps");


SEC("tc")
int tc_filter(struct __sk_buff * ctx) {

    unsigned long long ntime    = 0LL;

    struct tcp_snapshot_t 
        snapshot = {

        .valid  = 0U,
        .srcip  = 0U, 
        .dstip  = 0U,
        .srcprt = 0U,
        .dstprt = 0U,

        .ack = 0U,
        .syn = 0U,
        .urg = 0U,
        .fin = 0U,
        .rst = 0U,
        .psh = 0U
    };

    make_tcp_snapshot(
        (void *)(long)ctx->data, 
        (void *)(long)ctx->data_end, &snapshot);

	// bpf_printk("Got IP packet: SRC IP = %u",    snapshot.srcip);
    // bpf_printk("Got IP packet: DST IP = %u",    snapshot.dstip);
    // bpf_printk("Got IP packet: Interface = %u", ctx->ifindex);

    if(!snapshot.valid) 
        return TC_ACT_OK;
    
    struct key_t key = {
        .srcip   = snapshot.srcip,
        .dstip   = snapshot.dstip,
        .srcprt  = snapshot.srcprt,
        .dstprt  = snapshot.dstprt,
    };  

    ntime = bpf_ktime_get_ns();

    struct value_t *value;
    struct value_t  new_value = {
        .timestamp = ntime,
        .ifindex   = ctx->ifindex
    };

    value = bpf_map_lookup_elem(&fib, &key);
    if(!value) { // If there is not match in the map, this a brand-new connection
        bpf_map_update_elem(&fib, &key, &new_value, BPF_NOEXIST);
    }   
    return TC_ACT_OK;
}


SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {

    struct tcp_snapshot_t 
        snapshot = {

        .valid  = 0U,
        .srcip  = 0U, 
        .dstip  = 0U,
        .srcprt = 0U,
        .dstprt = 0U,

        .ack = 0U,
        .syn = 0U,
        .urg = 0U,
        .fin = 0U,
        .rst = 0U,
        .psh = 0U
    };

    make_tcp_snapshot(
        (void *)(long)ctx->data, 
        (void *)(long)ctx->data_end, &snapshot);

    if(!snapshot.valid) 
        return XDP_DROP;

    struct key_t key = {
        .dstip   = snapshot.srcip,
        .srcip   = snapshot.dstip,
        .dstprt  = snapshot.srcprt,
        .srcprt  = snapshot.dstprt,
    };  
    struct value_t *value;

    value = bpf_map_lookup_elem(&fib, &key);
    if(value) { // There is a match in the map, accelerate!
        bpf_printk("Accelerating a packet: FROM %u TO %u\n", key.dstprt, key.srcprt);
        bpf_redirect(1, 0);
    }
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";
