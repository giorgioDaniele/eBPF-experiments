import bcc
import time
import os
import ipaddress
import requests

def integer_to_ip(int_ip):
    return ipaddress.ip_address(int_ip).__str__()

def print_src_info(info):
    print(f'  Country: {info["country"]}\n  Region: {info["regionName"]}\n  City: {info["city"]}\n  ISP: {info["isp"]}\n  AS: {info["as"]}')
    return

def lookup_ip(ip):
    # Make a GET request to the API endpoint
    response = requests.get(f'http://ip-api.com/json/{ip}')
    # Check the response status code
    if response.status_code == 200:
    # Successful request
        object = response.json()  # Parse the response as JSON
        print_src_info(object)
    else:
        # Failed request
        print('Error:', response.status_code)
    return 0


BPF_SOURCE_FILE = 'main.c'
FUNCTION        = "monitor"
MAP             = "connections"
PERIOD          = 30

device      = "wlp1s0" 
bpf_program = bcc.BPF(src_file=BPF_SOURCE_FILE) 
function    = bpf_program.load_func(FUNCTION, bcc.BPF.XDP)
bpf_map     = bpf_program.get_table(MAP)
bpf_program.attach_xdp(device, function, 0)



def on_exit():
    #system('clear')
    print("Removing filter from device")
    bpf_program.remove_xdp(device, 0)
    #sleep(2)
    print("Removed")
    print("Bye!")
    #sleep(2)
    #system('clear')


os.system('clear')
print("----------------------------------")
print("Enter CTRL + C to stop XDP program")
print("----------------------------------")
while True:
    try:
        current_time = time.strftime('%H.%M.%S:')
        print(f'Ongoing connections at {current_time}\n')
        for key, value in bpf_map.items():
          print(f'  Src IP: {integer_to_ip(key.src_ip)}')
          print(f'  Dst Port: {key.dst_port}\n  Src Port: {key.src_port}')
          print(f'  Packets exchanged: {value.packets}\n  Bytes exchanged: {value.bytes}')
          lookup_ip(integer_to_ip(key.src_ip))
          print("\n")
        print("---------------------------------------")
        time.sleep(PERIOD)
    except KeyboardInterrupt:
        on_exit()
        break