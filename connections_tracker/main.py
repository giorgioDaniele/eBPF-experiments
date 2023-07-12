from bcc import BPF
import time
import os
import ipaddress

def integer_to_ip(int_ip):
    return ipaddress.ip_address(int_ip).__str__()

BPF_SOURCE_FILE = 'main.c'
FUNCTION        = "monitor"
MAP             = "connections"

device      = "wlp1s0" 
bpf_program = BPF(src_file=BPF_SOURCE_FILE) 
function    = bpf_program.load_func(FUNCTION, BPF.XDP)
bpf_map     = bpf_program.get_table(MAP)
bpf_program.attach_xdp(device, function, 0)


os.system('clear')
print("Monitoring traffic, hit CTRL+C to stop")
while True:
    try:
        time.sleep(1)
        current_time = time.strftime('%H.%M.%S:')
        print(f'Ongoing connections at {current_time}')
        for key, value in bpf_map.items():
          print(f'Dst IP: {integer_to_ip(key.dst_ip)} Src IP: {integer_to_ip(key.src_ip)}')
          print(f'Dst Port: {key.dst_port} Src Port: {key.src_port}')
          print(f'Packets: {value.packets} Bytes: {value.bytes}\n')
        print("---------------------------------------")
    except KeyboardInterrupt:
        print("Removing filter from device")
        break
bpf_program.remove_xdp(device, 0)