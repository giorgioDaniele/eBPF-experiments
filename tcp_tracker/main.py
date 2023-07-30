from bcc       import BPF
from pyroute2  import IPRoute
from time      import sleep
from time      import strftime
from os        import system
from ipaddress import ip_address
import socket

iproute = IPRoute()


def format_ip_port(ip, port):
    # Format IP address to 15 characters, right-aligned
    formatted_ip = "{:>15}".format(ip)
    # Format port to 5 characters, left-aligned
    formatted_port = "{:<5}".format(port)
    # Combine the formatted IP and port with a colon separator
    formatted_ip_port = "{}:{}".format(formatted_ip, formatted_port)
    return formatted_ip_port

def format_stats(bytes, packets): 

    overmultiples = [' B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
    idx = 0

    while bytes >= 1024 and idx < len(overmultiples) - 1:
        bytes /= 1024.0
        idx += 1

    formatted_bytes   = "{:.2f} {}".format(bytes, overmultiples[idx])
    formatted_bytes   = "{:>10}".format(formatted_bytes)
    formatted_packets = "{:>10}".format(packets)
    return "{} {} packets".format(formatted_bytes, formatted_packets)

def main():
    """
        Load program and its function
    """
    bpf_prog = BPF(src_file="bpf.c")
    function = bpf_prog.load_func("trace_tcp_connections", BPF.SCHED_CLS)
    bpf_tabl = bpf_prog.get_table('session_data')
    """
        Lookup for an interface called "wlp1s0"
        Notice that it may return many results,
        but I want the first one
    """
    index      = iproute.link_lookup(ifname = "wlp1s0")[0]
    addresses  = iproute.get_addr(index=index)
    ipaddress = 0
    for addr in addresses:
        if addr['family'] == socket.AF_INET:
            ipaddress = addr['attrs'][0][1]
    print(str(ipaddress))
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
    system('clear')
    print("########################################################")
    print("Hit CTRL + C to stop eBPF program :)")
    print("########################################################")
    while True:
        try:
            timestamp = strftime('%H:%M:%S')
            print(f"Trace at: {timestamp}")
            for k, v in bpf_tabl.items():
                formatted_src   = format_ip_port(str(ip_address(k.src_ip)), int(k.src_port))
                formatted_dst   = format_ip_port(str(ip_address(k.dst_ip)), int(k.dst_port))
                formatted_stats = format_stats(int(v.bts), int(v.pkt))
                print(f"#       Session: {formatted_src} -> {formatted_dst} | {formatted_stats}")
            sleep(2)
        except KeyboardInterrupt:
            break
    iproute.tc("del", "clsact", index)
    return

if __name__ == "__main__":
    main()