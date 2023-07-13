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


    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;
    struct iphdr  *ip  = data + sizeof(struct ethhdr);
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);


    // Check if the packet is an IPv4 TCP packet
    if (eth->h_proto != __constant_htons(ETH_P_IP) || ip->protocol != 0x06)
        return XDP_PASS;

    // Check if the packet's destination port is 80 (HTTP)
    if (tcp->source == __constant_htons(80)) {
         // Calculate header sizes
        int eth_header_size = sizeof(struct ethhdr);
        int ip_header_size  = ip->ihl * 4;
        int tcp_header_size = tcp->doff * 4;
     
        struct event_data http_packet = {
            .bytes_before_http = (unsigned int) eth_header_size + ip_header_size + tcp_header_size,
        };

        // Log the header sizes
        bpf_trace_printk("Ethernet Header Size: %d\n", eth_header_size);
        bpf_trace_printk("IP Header Size: %d\n",       ip_header_size);
        bpf_trace_printk("TCP Header Size: %d\n",      tcp_header_size);
        events.perf_submit_skb(ctx, packet_len, &http_packet, sizeof(http_packet));
    }
    return XDP_PASS;
}
