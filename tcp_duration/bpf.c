#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <linux/pkt_cls.h>




    struct snapshot_t {

        unsigned int  valid;
        unsigned int  src_ip; unsigned int src_port;
        unsigned int  dst_ip; unsigned int dst_port;

        unsigned int syn;
        unsigned int rst;
        unsigned int fin;
        unsigned int urg;
        unsigned int ack; 
        unsigned int psh;

    };

    struct tcp_packet {

        unsigned int  src_ip; 
        unsigned int src_port;
        unsigned int  dst_ip;
        unsigned int dst_port;

    };

#define MAX_SIZE 512

    struct key_t {
        unsigned int  src_ip; 
        unsigned int  src_port;
        unsigned int  dst_ip; 
        unsigned int  dst_port;
    };
    struct value_t {
        unsigned long SYN_timestamp;
        unsigned long FIN_timestamp;
    };


    BPF_PERF_OUTPUT(output);
    struct data_t {
        unsigned int  src_ip; 
        unsigned int  src_port;
        unsigned int  dst_ip; 
        unsigned int  dst_port;
        unsigned long duration_ns;
    };

    BPF_HASH(connections, struct key_t, struct value_t, MAX_SIZE);


static __always_inline void *move_on
    (void *pointer, unsigned char offset);
static __always_inline int   is_okay
    (void *pointer, unsigned char offset, void *end);
static __always_inline int   is_ipv4
    (unsigned short protocol);
static __always_inline int   is_tcp
    (unsigned char protocol);
static __always_inline void get_snapshot
    (void * data, void * data_end, struct snapshot_t * snapshot);


int trace_tcp_duration (struct __sk_buff * ctx) {

    unsigned long timestamp = bpf_ktime_get_ns();
    unsigned int  index     = 0;

    struct snapshot_t 
        snapshot = {

        .valid    = 0U,
        .src_ip   = 0U, 
        .dst_ip   = 0U,
        .src_port = 0U, 
        .dst_port = 0U,

        .ack = 0U,
        .syn = 0U,
        .urg = 0U,
        .fin = 0U,
        .rst = 0U,
        .psh = 0U
    };

    get_snapshot(
        (void *)(long)ctx->data, 
        (void *)(long)ctx->data_end, &snapshot);

    if(!snapshot.valid) 
        return TC_ACT_OK;

    if(snapshot.syn == 1 && 
        snapshot.ack == 0) {
        // A new connection has started    
        struct key_t
            new_key = {
            .src_ip    = snapshot.src_ip, 
            .dst_ip    = snapshot.dst_ip,
            .src_port  = snapshot.src_port, 
            .dst_port  = snapshot.dst_port,
        };
        struct value_t 
            new_value = {
            .SYN_timestamp = bpf_ktime_get_ns(),
            .FIN_timestamp = 0U,
        };
        connections.update(&new_key, &new_value);
    }

    // I expect to see FIN packets in both directions,
    // but I only care about the ones which are incoming
    // from the server, so reverse the key
    if(snapshot.fin == 1) {

        struct key_t
            new_reverse_key = {
            .src_ip    = snapshot.dst_ip, 
            .dst_ip    = snapshot.src_ip,
            .src_port  = snapshot.dst_port, 
            .dst_port  = snapshot.src_port,
        };

        struct value_t * value = connections.lookup(&new_reverse_key);
        if(value == NULL) {
            return TC_ACT_OK;
        }

        unsigned long *FIN_timestamp  = &value->FIN_timestamp;
        __sync_lock_test_and_set(FIN_timestamp, bpf_ktime_get_ns());

        struct data_t data = {
            .src_ip   = new_reverse_key.src_ip,
            .dst_ip   = new_reverse_key.dst_ip,
            .src_port = new_reverse_key.src_port,
            .dst_port = new_reverse_key.dst_port,
            // Get duration in nanoseconds
            .duration_ns = (value->FIN_timestamp - value->SYN_timestamp)
        };
        // Purge processed connections
        connections.delete(&new_reverse_key);
        output.perf_submit(ctx, &data, sizeof(data));

    }

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
static __always_inline void get_snapshot
    (void * data, void * data_end, struct snapshot_t * snapshot) {

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

    snapshot->valid    = 1U;

    snapshot->src_ip   = (unsigned int)__constant_ntohl(ip->saddr);
    snapshot->dst_ip   = (unsigned int)__constant_ntohl(ip->daddr);
    snapshot->src_port = (unsigned int)__constant_ntohs(tcp->source);
    snapshot->dst_port = (unsigned int)__constant_ntohs(tcp->dest);

    snapshot->ack = (unsigned int)tcp->ack;
    snapshot->syn = (unsigned int)tcp->syn;
    snapshot->urg = (unsigned int)tcp->urg;
    snapshot->fin = (unsigned int)tcp->fin;
    snapshot->rst = (unsigned int)tcp->rst;
    snapshot->psh = (unsigned int)tcp->psh;

    return;
}