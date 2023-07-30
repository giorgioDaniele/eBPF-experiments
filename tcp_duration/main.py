from re        import findall
from bcc       import BPF
from pyroute2  import IPRoute
from socket    import AF_INET
from os        import system
from ipaddress import ip_address
from time      import time

import matplotlib.pyplot as plt

iproute = IPRoute()

"""
    Load program and its function
"""

fd = open("statistics.dat", "w")

bpf_prog = BPF(src_file="bpf.c")
function = bpf_prog.load_func("trace_tcp_duration", BPF.SCHED_CLS)
bpf_stat = bpf_prog.get_table('output')

def normalize(num):
    return int(num) / 1_000_000_000

def get_timings (): 

    timings = []
    with open("statistics.dat", "r") as file:
        for line in file:
            # Define the regular expression pattern to match the "us" timing
            pattern = r'Duration: (\d+)'
            # Find all occurrences of the pattern in the line
            time_parts = findall(pattern, line)
            # Add the time parts to the 'us_timings' list
            timings.extend(time_parts)
        # Create a frequency histogram graph
        timings = list(map(normalize, timings))
    return timings

def format_ip_port(ip, port):
    # Format IP address to 15 characters, right-aligned
    formatted_ip = "{:>15}".format(ip)
    # Format port to 5 characters, left-aligned
    formatted_port = "{:<5}".format(port)
    # Combine the formatted IP and port with a colon separator
    formatted_ip_port = "{}:{}".format(formatted_ip, formatted_port)
    return formatted_ip_port

"""
def format_time (ns_value):

    multiples = ['ns', 'us', 'ms', 's']
    current_value    = ns_value
    current_multiple = multiples[0]

    for multiple in multiples:
        if current_value < 1000:
            break
        current_value /= 1000
        current_multiple = multiple

    formatted_time   = "{:.2f} {}".format(current_value, current_multiple)
    formatted_time   = "{:>10}".format(formatted_time)
    return "{}".format(formatted_time)
"""

def print_event(cpu, data, size):
    data = bpf_stat.event(data)
    formatted_src   = format_ip_port(str(ip_address(data.src_ip)), int(data.src_port))
    formatted_dst   = format_ip_port(str(ip_address(data.dst_ip)), int(data.dst_port))
    """formatted_time  = format_time(data.duration_ns)
    print(f"{formatted_src} -> {formatted_dst} | {formatted_time}", file=fd)"""
    print(f"{formatted_src} -> {formatted_dst} | Duration: {data.duration_ns}", file=fd)
    return


def main():
    """
        Lookup for an interface called "wlp1s0"
        Notice that it may return many results,
        but I want the first one
    """
    index      = iproute.link_lookup(ifname = "wlp1s0")[0]
    addresses  = iproute.get_addr(index=index)
    """
    ipaddress = 0
    for addr in addresses:
        if addr['family'] == AF_INET:
            ipaddress = addr['attrs'][0][1]"""
    #print(str(ipaddress))
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

    bpf_stat.open_perf_buffer(print_event)
    duration = 10  # Change this to the desired duration in seconds
    print(f"Writing on statistics.dat for {duration} seconds...")
    # Get the current time in seconds
    start_time = time()

    while (time() - start_time) < duration:
        try:
            bpf_prog.perf_buffer_poll()
        except KeyboardInterrupt:
            break
    iproute.tc("del", "clsact", index)
    fd.close()
    timings = get_timings()
    plt.hist(timings, bins=20, edgecolor='black', histtype='bar')
    # Add labels and title
    plt.xlabel('Timings (in s)')
    plt.ylabel('Frequency')
    plt.title('Timings Distribution')
    # Show the graph
    plt.show()
    return


if __name__ == "__main__":
    main()