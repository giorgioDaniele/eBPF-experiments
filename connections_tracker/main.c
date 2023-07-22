#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Weverything"

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define ETHERTYPE_IPv4 0x0800
#define PROTOCOL_TCP   0x06
#define IS_NOT_ETHERTYPE_IP(ethtype)  ((ethtype)  != ETHERTYPE_IPv4)
#define IS_NOT_PROTOCOL_TCP(protocol) ((protocol) != PROTOCOL_TCP)

#define IT_DOES_NOT_EXISTS(value) ((value) == NULL)

struct key_t {

    __u32 srcip;
    __u32 dstip;
    __u16 sport;
    __u16 dport;

};

struct value_t {

    __u64 bytes;
    __u64 packets;

};


BPF_HASH(connections, struct key_t, struct value_t, 256);

int tcp_stats_reporting (struct xdp_md *ctx) {

    void * data_end = (void *)(long)ctx->data_end;
    void * data     = (void *)(long)ctx->data;

    struct ethhdr * ethernet_layer;
    struct iphdr  * ip_layer;
    struct tcphdr * tcp_layer;

    ethernet_layer = (struct ethhdr *) data;
    if(ethernet_layer + 1 > data_end)
        return XDP_PASS;
    if(IS_NOT_ETHERTYPE_IP(__constant_ntohs(ethernet_layer->h_proto)))
        return XDP_PASS;
    
    ip_layer = (struct iphdr *) (data + sizeof(struct ethhdr));
    if(ip_layer + 1 > data_end)
        return XDP_PASS;
    if(IS_NOT_PROTOCOL_TCP((ip_layer->protocol)))
        return XDP_PASS;

    tcp_layer = (struct tcphdr *) (data + sizeof(struct ethhdr) + sizeof(struct tcphdr));
    if(tcp_layer + 1 > data_end)
        return XDP_PASS;
    
    struct key_t key = {
        .srcip = __constant_ntohl(ip_layer->saddr),   .dstip = __constant_ntohl(ip_layer->daddr),
        .sport = __constant_ntohs(tcp_layer->source), .dport = __constant_ntohs(tcp_layer->dest)
    };
    struct value_t value = {
        .bytes = (__u64) 0, .packets = (__u64) 0
    };

    struct value_t * previous_value = connections.lookup(&key);

    if(IT_DOES_NOT_EXISTS(previous_value)) {
        connections.insert(&key, &value);
    } else {
        value.bytes   += (__u64) (data_end - data);
        value.packets += (__u64) 1;
        connections.update(&key, &value);
    }
    return XDP_PASS;
}

#pragma clang diagnostic pop