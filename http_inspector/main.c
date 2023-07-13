#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>

#define LENGTH 1500

BPF_PERF_OUTPUT(events);

struct event_data {

    unsigned long long hours;
    unsigned long long minutes;
    unsigned long long seconds;
    unsigned int packet_len;
    unsigned char* packet_buffer;
};

static unsigned long get_nsecs(void) {
    return bpf_ktime_get_ns();
}

int http_monitor (struct xdp_md *ctx) {

    
    unsigned long long timestamp_ns  = get_nsecs();
    unsigned long long timestamp_sec = timestamp_ns / 1000000000;
    
    struct event_data new_packet_received = {
        .hours   = timestamp_sec / 3600,
        .minutes = (timestamp_sec % 3600) / 60,
        .seconds = timestamp_sec % 60,
    };

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
        bpf_trace_printk("-----------------------------------------------------------------");
        bpf_trace_printk("Packet Bytes = %d START POINTER = 0x%x END POINTER = 0x%x", packet_len, data, data_end);
        new_packet_received.packet_buffer =  (unsigned char*) data;
        new_packet_received.packet_len    =  packet_len;
        events.perf_submit_skb(ctx, packet_len, &new_packet_received, sizeof(new_packet_received));
        bpf_trace_printk("-----------------------------------------------------------------");
    }
    return XDP_PASS;
}
