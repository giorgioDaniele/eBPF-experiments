#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <signal.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf_legacy.h>
#include <time.h>
#include <sys/sysinfo.h>

#include "bpf_dplane.h"

#define IP_ADDRESS_FROM_OCTETS(fst, snd, thd, fth)\
    ((fst << 24) + (snd << 16) + (thd << 8) + (fth))

static volatile sig_atomic_t exiting = 0;
static void sig_int(int signo) {
	exiting = 1;
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

static int 
from_ascii_to_int (
    char *addr) {

    unsigned int fst;
    unsigned int snd;
    unsigned int thd;
    unsigned int fth;

    sscanf(addr, "%u.%u.%u.%u", &fst, &snd, &thd, &fth);
    return IP_ADDRESS_FROM_OCTETS(fst, snd, thd, fth);
}

static void
from_int_to_ascii (
    unsigned int value, 
    char *addr) {
    sprintf(addr, "%u.%u.%u.%u",
        (value >> 24) & 0xFF,
        (value >> 16) & 0xFF,
        (value >> 8) & 0xFF,
         value & 0xFF);
    return;
}

static unsigned long long
get_nsecs (void) {

    /* Get monotonic clock time */
    struct timespec monotime;
    clock_gettime(CLOCK_MONOTONIC, &monotime);
    return (unsigned long long) 
        monotime.tv_sec * 1000000000ULL + 
            (unsigned long long) 
        monotime.tv_nsec;
}

void 
refresh_fib(int fd) {

    struct key_t   key;
    struct key_t   next_key;
    struct value_t value;

    unsigned long long lifetime;
    unsigned long long now;
    unsigned int active     = 0;
    unsigned int not_active = 0;
    unsigned int total      = 0;

    char srcip [INET_ADDRSTRLEN];
    char dstip [INET_ADDRSTRLEN];

    char *dev  = malloc((IF_NAMESIZE + 1) * sizeof(char));

    now = get_nsecs();
    printf("------------------------------\n");
    memset(&next_key, 0, sizeof(next_key));

    while (bpf_map_get_next_key(fd, &next_key, &key) == 0) {
        if (bpf_map_lookup_elem(fd, &key, &value) == 0) {   

            total ++;
            from_int_to_ascii(key.srcip, srcip);
            from_int_to_ascii(key.dstip, dstip);
            dev = if_indextoname(value.ifindex, dev);

            lifetime = ((now - value.timestamp) / 1000000000ULL);
            if(lifetime >= 15UL) {
                bpf_map_delete_elem(fd, &key);
                not_active ++;

            } else {
                printf("\n\
    [SRC IP]   = %s\n\
    [DST IP]   = %s\n\
    [SRC PORT] = %u\n\
    [DST PORT] = %u\n\
    [IFINDX]   = %u (%s)\n\
    [LIFETIME] = %llu [s]\n\n", 
                srcip,
                dstip,
                key.srcprt,  
                key.dstprt, 
                value.ifindex, dev, lifetime);
                active ++;
            }
        } else {
            printf("Error on dumping the map\n");
            return;
        } 
        next_key = key;
    }
    printf("Purged: %u, Active: %u, Total = %d\n", not_active, active, total);
    printf("------------------------------\n");
    free(dev);
    return;
}


int main(int argc, char **argv) {

    int xdp_prog_fd;
    int tce_prog_fd;

    int emap_fd;
    int index;

    struct dplane_bpf *dplane;

    // TCE management
    int    hook_er;
    int    hook_ok = 0;
    struct bpf_tc_hook hook;
    struct bpf_tc_opts tce_opts;

    // XDP management
    int flags;
    struct bpf_xdp_attach_opts xdp_opts;

    signal(SIGINT, sig_int);

    if((dplane = dplane_bpf__open_and_load()) == NULL) {
        printf("Error: failed to open BPF progeton\n");
        return 1;
    }

    // Get TC program descriptor
    if((tce_prog_fd = bpf_program__fd(dplane->progs.tc_filter)) <= 0) {
        printf("Error: failted to get TC egress program descriptor\n");
        return 1;
    }
    
    // Get XDP program descriptor
    if((xdp_prog_fd = bpf_program__fd(dplane->progs.xdp_filter)) <= 0) {
        printf("Error: failted to get XDP program descriptor\n");
        return 1;
    }


    index = if_nametoindex("wlp1s0");

    // Hook creation
    hook.ifindex      = index;
    hook.attach_point = BPF_TC_EGRESS;
    hook.parent       = 0;
    hook.sz = sizeof(struct bpf_tc_hook);

    // Hook options
    tce_opts.prog_fd      = tce_prog_fd;
    tce_opts.handle       = 1;
    tce_opts.priority     = 1;
    tce_opts.sz = sizeof(struct bpf_tc_opts);

    // Create the hook with the previous specs
    // bpf_tc_hook_create() is zero if successfull
    if((hook_er = bpf_tc_hook_create(&hook)) != 0)  
        hook_ok = 1;

    if (hook_er && hook_er != -EEXIST) {
		printf("Failed to create TC hook\n");
        goto error;
	}

	if (bpf_tc_attach(&hook, &tce_opts) != 0) {
        printf("Error: failed to attach program to TC egress\n");
        goto error;
	}


    // XDP management
    flags = 0;

    if(bpf_xdp_attach(index, xdp_prog_fd, flags, NULL) != 0) {
        printf("Error: failed to attach program to XDP hook\n");
        goto error;
    }

    if((emap_fd = bpf_map__fd(dplane->maps.fib)) <= 0) {
        printf("Error: failed to get map descriptor\n");
        goto error;
    }

	while (!exiting) {
        // Dump the map each 5 second
		sleep(5);
        refresh_fib(emap_fd);
	}


	tce_opts.flags = tce_opts.prog_fd = tce_opts.prog_id = 0;
	if ((bpf_tc_detach(&hook, &tce_opts)) != 0) {
		printf("Failed to detach program from TC egress\n");
        goto error;
    }

    if ((bpf_xdp_detach(index, flags, NULL)) != 0) {
		printf("Failed to detach program from XDP\n");
        goto error;
    }

    return 0;

error:

    if(hook_ok)
        bpf_tc_hook_destroy(&hook);
    dplane_bpf__destroy(dplane); 
    return 1;

}
