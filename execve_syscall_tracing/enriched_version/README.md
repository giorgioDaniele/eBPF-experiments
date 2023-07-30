# ```execve()``` tracing (Enriched Version)

The eBPF program is injected into the kernel to incercept whenever syscall ```execve()``` is invoked. Notice that ```execve()``` executes the program referred to by pathname. This causes the program that is currently being run by the calling process to be replaced with a new program, with newly initialized stack, heap, and (initialized and uninitialized) data segments.

## Workflow

### C-side

This file is the one which is going to be injected into the kernel. In order to transfer data from kernel space to user space, that is the ```.py``` script. Instead of using a hash map, I use a ring buffer, that is shared memory area from kernel space to user space. With ring buffers, I can transfer more general data from eBPF routine to user space reader. It is a matter of providing a structure for such data.

```c
BPF_PERF_OUTPUT(output);
struct data_t {
    int pid;
    int uid;
    char command[16];
    char message[100];
};
```

The eBPF routine is straightforward. I rely on some useful helper to get access to relevant information.

```c
unsigned int user_id = 0;
unsigned int USER_ID_MASK = 0xFFFFFFF;
...
struct data_t data = {};
...
data.pid = bpf_get_current_pid_tgid() >> 32;
data.uid = bpf_get_current_uid_gid() & USER_ID_MASK;

// Use this to get the command name, that is the process
// which has triggered the execve, and therefore the eBPF program
// Notice that it is a string!
bpf_get_current_comm(&data.command,  sizeof(data.command));
// According to the documentation, this is the signature:
// int bpf_probe_read_kernel(void *dst, int size, const void *src)
// This copies size bytes from kernel address space to the BPF stack,
// so that BPF can later operate on it
bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
    
```
-----
### Python-side

The user space program checks continuosly if the reader pointer points
at a different location than the writer one. If so, the eBPF has just
uploaded new data and the Python script can manipulate it.

```python
while True:
    try:
        program.perf_buffer_poll()
    except KeyboardInterrupt:
        break
print("#####################################")
```

-----
### Demo

```shell
$ sudo python main.py

Run! Hit CTRL + C to stop eBPF script
...
PID = 75749, User ID = 1001, Command =  bash, Message = This a message
PID = 75750, User ID = 1001, Command =  bash, Message = This a message
PID = 75752, User ID = 1001, Command =  soffice, Message = This a message
PID = 75753, User ID = 1001, Command =  soffice, Message = This a message
PID = 75755, User ID = 1001, Command =  soffice, Message = This a message
```
-----

### Altert
If you run the eBPF routine from VSCode built-in terminal, the number gets
higher and higher. Do not panic! VSCode runs periodically a cpuUsage.sh under the hood.