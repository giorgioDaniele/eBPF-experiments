from bcc  import BPF
from os   import system


program = BPF(src_file='bpf.c')
syscall = program.get_syscall_fnname('execve')
map     = program.get_table('output')
program.attach_kprobe(event=syscall, fn_name='execve_monitor')

def print_event(cpu, data, size):
    data = map.event(data)
    print(f"PID = {data.pid}, User ID = {data.uid}, Command =  {data.command.decode()}, Message = {data.message.decode()}")

def eBPF_program():
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

if __name__ == "__main__":
    eBPF_program()
