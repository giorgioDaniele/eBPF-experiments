from bcc  import BPF
from os   import system
from time import sleep

USE_RING_BUFFER = 1

program = BPF(src_file='bpf_program.c')
syscall = program.get_syscall_fnname('execve')
map     = program.get_table('output' if USE_RING_BUFFER else 'counter')
program.attach_kprobe(event=syscall, fn_name='execve_monitor')


def print_event(cpu, data, size):
    data = map.event(data)
    print(f"PID = {data.pid}, User ID = {data.uid}, Command =  {data.command.decode()}, Message = {data.message.decode()}")

def eBPF_program_with_ring_buffer():
    system('clear')
    print("#####################################")
    print("Run! Hit CTRL + C to stop eBPF script")
    print("#####################################")
    map.open_perf_buffer(print_event)
    while True:
        try:
            program.perf_buffer_poll()
        except KeyboardInterrupt:
            break
    print("#####################################")


def eBPF_program():
    system('clear')
    print("#####################################")
    print("Run! Hit CTRL + C to stop eBPF script")
    print("#####################################")
    while True:
        try:
            sleep(5)
            s = ""
            for k,v in map.items():
                s += f"User ID {k.value} has invoked {v.value} times execve syscall!\t"
            print(s)
        except KeyboardInterrupt:
            break
    print("#####################################")
if __name__ == "__main__":
    eBPF_program_with_ring_buffer()
