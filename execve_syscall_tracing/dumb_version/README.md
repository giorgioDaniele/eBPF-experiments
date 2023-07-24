# Dumb Version

The eBPF program is injected into the kernel to incercept whenever syscall **execve()** is invoked. Notice that execve() executes the program referred to by pathname. This causes the program that is currently being run by the calling process to be replaced with a new program, with newly initialized stack, heap, and (initialized and uninitialized) data segments.

## Workflow

### C-side

This file is the one which is going to be injected into the kernel. In order to transfer data from kernel space to user space, that is the .py script, I have created a hash map. I do not care about internals, I just rely on bcc APIs for such macro. All I have to do is providing a name, the key's size, as well as the value's one. Eventually, I have to include the maximum number of keys. That is it!

```c
BPF_HASH(counter_table, unsigned int, unsigned int, 1024);
```

The eBPF routine is straightforward. I rely on some useful helper to get access to relevant information.

```c
unsigned int user_id = 0;
unsigned int USER_ID_MASK = 0xFFFFFFF;
...
user_id = bpf_get_current_uid_gid() & USER_ID_MASK;
```
-----
### Python-side

The user space program has to check continuosly for map content, by spinning on infinite loop until you hit CTRL + C, which causes the exit.

```python
while True:
    try:
        sleep(5)
        s = ""
        for k,v in map.items():
            s += f"User ID {k.value} has invoked {v.value} times execve syscall!\t"
        print(s)
    except KeyboardInterrupt:
        break
```

-----
### Demo

```shell
$ sudo python main.py

Run! Hit CTRL + C to stop eBPF script
#####################################
User ID 0 has invoked 2 times execve syscall!   User ID 1001 has invoked 16 times execve syscall!
User ID 0 has invoked 2 times execve syscall!   User ID 1001 has invoked 16 times execve syscall!
User ID 0 has invoked 3 times execve syscall!   User ID 1001 has invoked 16 times execve syscall! 
User ID 0 has invoked 3 times execve syscall!   User ID 1001 has invoked 17 times execve syscall! 
```
-----

### Altert
If you run the eBPF routine from VSCode built-in terminal, the number gets
higher and higher. Do not panic! VSCode runs periodically a cpuUsage.sh under the hood.