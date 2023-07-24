from bcc  import BPF
from os   import system
from time import sleep


program = BPF(src_file='bpf.c')
syscall = program.get_syscall_fnname('execve')
map     = program.get_table('counter_table')
program.attach_kprobe(event=syscall, fn_name='execve_monitor')



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
    eBPF_program()
