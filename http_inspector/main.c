#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>

#define LENGTH 1500

BPF_PERF_OUTPUT(events);

struct event_data {
    unsigned int bytes_before_http;
};

int http_monitor (struct xdp_md *ctx) {

    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    unsigned int packet_len = data_end - data;


    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr)  + sizeof(struct tcphdr) > data_end) { 
            return XDP_DROP; 
    }

    struct ethhdr *eth = data;
    struct iphdr  *ip  = data + sizeof(struct ethhdr);
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    unsigned short IP_PROT0 = 0x0800;
    unsigned short HTTP     = 80;
    unsigned char  TCP      = 0x6;

    if(__constant_htons(eth->h_proto) != IP_PROT0 || ip->protocol != TCP) {
        return XDP_PASS;
    } else if (__constant_htons(tcp->source) == HTTP) {
        unsigned int eth_header_size = sizeof(struct ethhdr);
        unsigned int ip_header_size  = ip->ihl * 4;
        unsigned int tcp_header_size = tcp->doff * 4;

        struct event_data bytes_before_http = {
            .bytes_before_http = 
                (unsigned int) 
                    eth_header_size + 
                    ip_header_size  + 
                    tcp_header_size };
        
        bpf_trace_printk("Ethernet Header Size: %d\n",  eth_header_size);
        bpf_trace_printk("IP Header Size: %d\n",        ip_header_size);
        bpf_trace_printk("TCP Header Size: %d\n",       tcp_header_size);
        events.perf_submit_skb(ctx, packet_len, &bytes_before_http, sizeof(bytes_before_http));        
    } else {
        return XDP_PASS;
    }
}