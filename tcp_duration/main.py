from re        import findall
from bcc       import BPF
from pyroute2  import IPRoute
from socket    import AF_INET
from os        import system
from ipaddress import ip_address
from time      import time

iproute = IPRoute()


fd = open("statistics.dat", "w")

bpf_prog = BPF(src_file="bpf.c")
function = bpf_prog.load_func("trace_tcp_duration", BPF.SCHED_CLS)
bpf_stat = bpf_prog.get_table('output')

def normalize(num):
    return int(num) / 1_000_000_000

def format_ip_port(ip, port):
    # Format IP address to 15 characters, right-aligned
    formatted_ip = "{:>15}".format(ip)
    # Format port to 5 characters, left-aligned
    formatted_port = "{:<5}".format(port)
    # Combine the formatted IP and port with a colon separator
    formatted_ip_port = "{}:{}".format(formatted_ip, formatted_port)
    return formatted_ip_port

def print_event(cpu, data, size):
    data = bpf_stat.event(data)
    formatted_src   = format_ip_port(str(ip_address(data.src_ip)), int(data.src_port))
    formatted_dst   = format_ip_port(str(ip_address(data.dst_ip)), int(data.dst_port))
    print(f"{formatted_src} -> {formatted_dst} | Duration: {data.duration_ns / 1_000_000_000} s", file=fd)
    return

def listent_at_events():

    system('clear')
    print("########################################################")
    print("Hit CTRL + C to stop eBPF program :)")
    print("########################################################")
    bpf_stat.open_perf_buffer(print_event)

    try:
        while True:
            bpf_prog.perf_buffer_poll()
    except KeyboardInterrupt:
        pass

    return

def main():

    """
        Lookup for an interface called "wlp1s0"
        Notice that it may return many results,
        but I want the first one
    """
    index      = iproute.link_lookup(ifname = "wlp1s0")[0]

    """
        The clsact qdisc provides a mechanism to attach integrated 
        filter-action classifiers to an interface, either at 
        ingress or egress, or both. The use case shown here is 
        using a bpf program (implemented elsewhere) to direct 
        the packet processing. The example also uses the direct-action 
        feature to specify what to do with each packet (pass, drop, redirect, etc.).
    """
    iproute.tc("add", "clsact", index)
    # Add ingress clsact
    iproute.tc("add-filter", "bpf", index, ":1", fd=function.fd, name=function.name,
        parent="ffff:fff2", classid=1, direct_action=True)
    # Add egress clsact
    iproute.tc("add-filter", "bpf", index, ":1", fd=function.fd, name=function.name,
        parent="ffff:fff3", classid=1, direct_action=True)
    
    # Listener
    listent_at_events()

    # Cleanup the environment
    iproute.tc("del", "clsact", index)
    fd.close()
    return


if __name__ == "__main__":
    main()
