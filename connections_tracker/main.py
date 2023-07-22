from ipaddress  import ip_address
from bcc        import BPF
from time       import sleep
from os         import system
from ctypes     import c_uint16, c_ulong, c_uint32
from  time      import time
from  datetime  import datetime
from  warnings  import filterwarnings

import argparse

# Suppress BCC warning messages
filterwarnings("ignore", category=Warning, module="bcc")

def integer_to_ip(int_ip):
    return ip_address(int_ip).__str__()

def print_time():
    timestamp = time()
    # Convert the timestamp to a human-readable format
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')


def on_exit(bpf_program, device):
    #system('clear')
    print("Removing filter from device")
    bpf_program.remove_xdp(device, 0)
    #sleep(2)
    print("Removed")
    print("Bye!")
    #sleep(2)
    #system('clear')

def xdp_progr(bpf_map, period, bpf_program, device):
    system('clear')
    print("----------------------------------")
    print("Enter CTRL + C to stop XDP program")
    print("----------------------------------")
    while True:
        try:
            print("------------------------------------------------------------------------")
            print(f" Connections report, [{print_time()}]: ")
            for key, value in bpf_map.items():
                srcip   = c_uint32(key.srcip)
                dstip   = c_uint32(key.dstip)
                sport   = c_uint16(key.sport)
                dport   = c_uint16(key.dport)
                
                bytes   = c_ulong(value.bytes)
                packets = c_ulong(value.packets)
                print(f"|    Source      IP:   {integer_to_ip(srcip.value)} (Remote server) ")
                print(f"|    Destination IP:   {integer_to_ip(dstip.value)} (My host)       ")
                print(f"|    Source      Port: {(sport.value)}                              ")
                print(f"|    Destination Port: {(dport.value)}                              ")
                print(f"|        Bytes:   {bytes.value}                                     ")
                print(f"|        Packets: {packets.value}                                   ")
            sleep(period)
        except KeyboardInterrupt:
            on_exit(bpf_program, device)
            break

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", type=str, required=True, help="Interface name")
    parser.add_argument("-p", "--period",    type=int, required=True, help="Period (number)")
    return parser.parse_args()


if __name__ == "__main__":

    args = parse_arguments()
    # Accessing the interface and period arguments
    interface_name = args.interface
    period_number  = args.period

    bpf_program = BPF(src_file="main.c") 
    function    = bpf_program.load_func("tcp_stats_reporting", BPF.XDP)
    bpf_map     = bpf_program.get_table("connections")
    bpf_program.attach_xdp(interface_name, function, 0)

    # Call XDP program
    xdp_progr(bpf_map, period_number, bpf_program, interface_name)