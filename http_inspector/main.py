from bcc import BPF
import ctypes as ct
import pyroute2
import socket
import datetime
import struct
import os


BPF_SOURCE_FILE = 'main.c'
FUNCTION        = "http_monitor"
MAP             = "connections"
PERIOD          = 30

device      = "wlp1s0" 
bpf_program = BPF(BPF_SOURCE_FILE)
function    = bpf_program.load_func(FUNCTION, BPF.XDP)
bpf_program.attach_xdp(device, function, 0)

def process_event(cpu, data, size):
    # Define the event data structure
    class EventData(ct.Structure):
        _fields_ = [
            ("hours",          ct.c_uint64),
            ("minutes",        ct.c_uint64),
            ("seconds",        ct.c_uint64),
            ("packet_len",     ct.c_uint32),
            ("packet_buffer",  ct.c_ubyte * (size - ct.sizeof(ct.c_ubyte))),
        ]
    event = ct.cast(data, ct.POINTER(EventData)).contents
    # Format the datetime object as hours:minutes:seconds
    print("Timestamp: {:02d}:{:02d}:{:02d}".format(event.hours, event.minutes, event.seconds))
    print(f"Length: {event.packet_len}")
    for element in event.packet_buffer[12:]:
        print("{:02x}".format(element), end=" ")
    print("")
    print("--------------------------------------------------------------")
    return

bpf_program["events"].open_perf_buffer(process_event)

os.system('clear')
print("Monitoring traffic, hit CTRL+C to stop")    
while True:
    try:
        #print()
        bpf_program.perf_buffer_poll()
    except KeyboardInterrupt:
        print("Removing filter from device")
        break
bpf_program.remove_xdp(device, 0)