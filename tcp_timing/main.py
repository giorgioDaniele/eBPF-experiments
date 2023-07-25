from   ipaddress import ip_address


import ctypes

from bcc  import  BPF
from time import  sleep
from os   import  system

BPF_SOURCE_FILE = 'script.c'
FUNCTION        = "trace_tcp_connections"
MAP             = "results"
PERIOD          = 5
DEVICE          = "wlp1s0" 


bpf_program = BPF(BPF_SOURCE_FILE)
function    = bpf_program.load_func(FUNCTION, BPF.XDP)
bpf_map     = bpf_program.get_table(MAP)
bpf_program.attach_xdp(DEVICE, function, 0)


def format_duration(duration_ns):
    # Define the units and their corresponding conversions
    units = {
        's':  1e9,
        'ms': 1e6,
        'μs': 1e3,
        'ns': 1
    }

    # Find the appropriate unit to use
    for unit in units:
        if duration_ns >= units[unit]:
            duration_val = duration_ns / units[unit]
            return f"{duration_val:.2f} {unit}"

    # If the duration is very small, display in nanoseconds
    return f"{duration_ns:.2f} ns"

def on_exit():
    #system('clear')
    print("Removing filter from device")
    bpf_program.remove_xdp(DEVICE, 0)
    #sleep(2)
    print("Removed")
    print("Bye!")
    #sleep(2)
    #system('clear')


system('clear')
print("----------------------------------")
print("Enter CTRL + C to stop XDP program")
print("----------------------------------")


while True:
    try:
        sleep(1)
        for key, value in bpf_map.items():

            src_ip     = ctypes.c_uint32(value.src_ip)
            dst_ip     = ctypes.c_uint32(value.dst_ip)

            src_port   = ctypes.c_uint16(value.src_port)
            dst_port   = ctypes.c_uint16(value.dst_port)
            
            start_time = ctypes.c_ulong(value.start_time)
            end_time   = ctypes.c_ulong(value.end_time)
            duration   = (end_time.value - start_time.value)

            print("### [ Connection ] ###")
            print(f"Src IP: {ip_address(src_ip.value)}:{src_port.value}, Dst IP: {ip_address(dst_ip.value)}:{dst_port.value}\n    Duration: {format_duration(duration)}")
            print()
    except KeyboardInterrupt:
        on_exit()
        break

"""
try:
    bpf_program.trace_print()
except KeyboardInterrupt:
    on_exit()
"""
