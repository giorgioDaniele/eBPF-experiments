#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>




struct connection {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int   src_ip;
    unsigned int   dst_ip;
};

struct statistics {
    unsigned long packets;
    unsigned long bytes;
};

BPF_HASH(connections, struct connection, struct statistics, 1024);

int monitor(struct xdp_md *ctx) {

    unsigned char UDP    = 0x17;
    unsigned char TCP    = 0x06;
    unsigned short HTTPS = 443;


    // Packet captured
    void *data     = (void *)(unsigned long)ctx->data;
    void *data_end = (void *)(unsigned long)ctx->data_end;

    unsigned short offset = 0;
    unsigned int   src_ip = 0;
    unsigned int   dst_ip = 0;
    unsigned short src_port = 0;
    unsigned short dst_port = 0;

    struct ethhdr *ethernet_header = data;
    offset = sizeof(*ethernet_header);
    if (data + offset > data_end) {
        bpf_trace_printk("Packet discarded because of layer 2\n");
        return XDP_DROP;
    }
    struct iphdr *ip_header = data + offset;
    offset += sizeof(*ip_header);
    if (data + offset > data_end) {
        bpf_trace_printk("Packet discarded because of layer 3\n");
        return XDP_DROP;
    }

    src_ip = (unsigned int)ip_header->saddr;
    dst_ip = (unsigned int)ip_header->daddr;

    if(ip_header->protocol == TCP) {
        struct tcphdr * tcp_header = data + offset;
        offset += sizeof(*tcp_header);
        if (data + offset > data_end) {
            bpf_trace_printk("Packet discarded because of layer 4\n");
            return XDP_DROP;
        }
        src_port = (unsigned short) tcp_header->source;
        dst_port = (unsigned short) tcp_header->dest;

        struct connection new_connection = {
            .src_ip   = __constant_htonl(src_ip),
            .dst_ip   = __constant_htonl(dst_ip),
            .src_port = __constant_htons(src_port),
            .dst_port = __constant_htons(dst_port),
        };
        struct statistics new_statistics = {
            .packets = 0,
            .bytes = 0,
        };
        struct statistics *current_statistics = connections.lookup_or_try_init(&new_connection, &new_statistics);
        if (!current_statistics) {
            return XDP_PASS;
        }
        __sync_fetch_and_add(&current_statistics->packets, 1);
        __sync_fetch_and_add(&current_statistics->bytes, (data_end - data));
    } 
    return XDP_PASS;
}
