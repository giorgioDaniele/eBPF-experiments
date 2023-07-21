#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct tcp_connection {
    
    __u64 start_time;
    __u64 end_time;

};

struct tcp_connection_duration {

    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;

    __u64 start_time;
    __u64 end_time;

};

BPF_HASH(connections, __u32, struct tcp_connection);
BPF_HASH(results,     __u32, struct tcp_connection_duration);

int trace_tcp_connections (struct xdp_md *ctx) {

    // Get access to packet buffer
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr* eth = data;
    if (eth + 1 > data_end) // C pointer math!
        return XDP_PASS;
    
    // Check if the packet is a IP packet
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr* ip = data + sizeof(struct ethhdr);
    if (ip + 1 > data_end)
        return XDP_PASS;

    // Check if the packet is a TCP packet
    if (ip->protocol != 0x06)
        return XDP_PASS;

    struct tcphdr* tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (tcp + 1 > data_end)
        return XDP_PASS;

    // Get the source and destination ports for uniquely identifying the connection

    __u32 src_ip   = __constant_ntohl(ip->saddr);
    __u32 dst_ip   = __constant_ntohl(ip->daddr);
    __u16 src_port = __constant_ntohs(tcp->source);
    __u16 dst_port = __constant_ntohs(tcp->dest);

    // Each connection is established by a client and a server. The client
    // sends packets to the a server port (destination port), while the server
    // sends packets to the a client port (source port). These two ports +
    // IP addresses defines a TCP connection;

    // Shift source port of 16-bit to left and concat destination port to have 
    // a key
    __u32 key = (src_port << 16) | dst_port;

    struct tcp_connection *connection;
    __u64 current_time = bpf_ktime_get_ns();

    // Try to find an existing connection in the BPF map
    connection = connections.lookup(&key);
    if (!connection) {
        // If the connection doesn't exist, create a new entry
        struct tcp_connection new_connection = {
            .start_time = current_time,
            .end_time   = 0,
        };
        connections.update(&key, &new_connection);
    } else if (tcp->fin) {
        // If it's a FIN packet, calculate and print the duration
        connection = connections.lookup(&key);
        if(connection) {
            struct tcp_connection_duration new_connection = {

                .start_time = connection->start_time,
                .end_time   = current_time,

                .src_ip     = src_ip,
                .dst_ip     = dst_ip,
                .src_port   = src_port,
                .dst_port   = dst_port,
            };

            results.update(&key, &new_connection);
            connections.delete(&key);
        }
    }

    return XDP_PASS;
}
