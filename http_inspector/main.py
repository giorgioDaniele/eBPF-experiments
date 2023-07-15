from bcc import BPF
import ctypes as ct
import os

BPF_SOURCE_FILE = 'main.c'
FUNCTION        = "http_monitor"
MAP             = "connections"
PERIOD          = 30

output_file = open("result.dump", "w")  # Open the file in write mode

device      = "wlp1s0" 
bpf_program = BPF(BPF_SOURCE_FILE)
function    = bpf_program.load_func(FUNCTION, BPF.XDP)
bpf_program.attach_xdp(device, function, 0)

def process_event(cpu, data, size):
    # Define the event data structure
    class EventData(ct.Structure):
        _fields_ = [
            ("bytes_before_http", ct.c_uint32),
            ("raw",               ct.c_ubyte * (size - ct.sizeof(ct.c_uint32))),
        ]
    event = ct.cast(data, ct.POINTER(EventData)).contents
    #Print metadata
    if(any(byte != 0x00 for byte in event.raw[event.bytes_before_http:])):
        print(f"Packet  Length: {size}", file=output_file)
        print(f"Header  Lenght: {event.bytes_before_http}", file=output_file)
        ascii_sequence = ''.join(chr(byte) for byte in event.raw[event.bytes_before_http:])
        print(ascii_sequence, file=output_file)
        print("", file=output_file)
        print("--------------------------------------------------------------", file=output_file)
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
output_file.close()