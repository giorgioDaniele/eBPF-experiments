from os  import system
from bcc import BPF
from ipaddress import ip_address
from ctypes    import c_uint16, c_uint32, c_ulong
from time      import sleep


bpf_program = BPF(src_file="bpf.c") 
function    = bpf_program.load_func("tcp_logger", BPF.XDP)
bpf_map     = bpf_program.get_table("connections")
bpf_program.attach_xdp('wlp1s0', function, 0)

def print_entry(k, v):
    # Please remember that k is of type struct key_t
    # To get access such data, I rely on cyptes
    src_ip   = str(ip_address(c_uint32(k.src_ip).value))
    dst_ip   = str(ip_address(c_uint32(k.dst_ip).value))
    src_port = str(c_uint16(k.src_port).value)
    dst_port = str(c_uint16(k.dst_port).value)

    bytes    = str(c_ulong(v.bytes).value)
    packets  = str(c_ulong(v.packets).value)

    print(f"-- [TCP connection ] --")
    print(f"[IP]\nSrc IP Address: {src_ip}\nDst IP Address: {dst_ip}\n[TCP]\nSrc Port: {src_port}\nDst Port: {dst_port}")
    print(f"        Bytes   = {bytes}\n        Packets = {packets}")
    print(f"-----------------------")
    return

def print_map():
    for k,v in bpf_map.items():
        print_entry(k, v)
    print("SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS")
    sleep(1)
    return

def eBPF_program ():
    system('clear')
    print("___________________________________")
    print("Enter CTRL + C to stop XDP program")
    print("___________________________________")
    print()
    print()
    while True:
        try:
            print_map()
        except KeyboardInterrupt:
            break
    bpf_program.remove_xdp('wlp1s0', 0)


if __name__ == "__main__":
    eBPF_program()
