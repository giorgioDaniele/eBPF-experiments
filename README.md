# eBPF-experiments

![Linux](https://img.shields.io/badge/platform-linux-yellow)
![Python](https://img.shields.io/badge/language-python-green)

A collection of experiments with eBPF, a technology that can run sandboxed programs in a privileged context such as the operating system kernel. Each project is powered by [bcc](https://github.com/iovisor/bcc/tree/master) toolkit.


# ```execve()``` tracing (Dumb Version)

The eBPF program is injected into the kernel to incercept whenever syscall ```execve()``` is invoked. Notice that ```execve()``` executes the program referred to by pathname. This causes the program that is currently being run by the calling process to be replaced with a new program, with newly initialized stack, heap, and (initialized and uninitialized) data segments.

## Workflow

### C-side

This file is the one which is going to be injected into the kernel. In order to transfer data from kernel space to user space, that is the ```.py``` script, I have created a hash map. I do not care about internals, I just rely on bcc APIs for such macro. All I have to do is providing a name, the key's size, as well as the value's one. Eventually, I have to include the maximum number of keys. That is it!

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
...
User ID 0 has invoked 2 times execve syscall!   User ID 1001 has invoked 16 times execve syscall!
User ID 0 has invoked 2 times execve syscall!   User ID 1001 has invoked 16 times execve syscall!
User ID 0 has invoked 3 times execve syscall!   User ID 1001 has invoked 16 times execve syscall! 
User ID 0 has invoked 3 times execve syscall!   User ID 1001 has invoked 17 times execve syscall! 
```
-----

### Altert
If you run the eBPF routine from VSCode built-in terminal, the number gets
higher and higher. Do not panic! VSCode runs periodically a cpuUsage.sh under the hood.

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

# TCP tracker

I successfully developed an eBPF program to inject into the Linux TC (Traffic Control) system, enabling me to trace TCP connections. The primary goal of this eBPF program was to monitor and gather valuable data from TCP sessions on the network. The eBPF program was attached to the TC ingress hook and the engress. In this way, I can capture both incoming and outcoming packets.

## Workflow

### C-side

Since each TCP connection is identified by the source IP address, the destination IP address, the source port and the destination port, I created ```struct key_t```

```c
struct key_t {
    unsigned int valid;
    unsigned int src_ip; unsigned int src_port;
    unsigned int dst_ip; unsigned int dst_port;
};
```

I used a BPF_HASH map, whose keys are instances of the previous C-struct, while the values are expressed by yet another C-struct called ```struct stat_t```.

```c
struct stat_t {
    unsigned long bts; // Bits/Bytes
    unsigned long pkt; // Packets  
};

BPF_HASH(session_data, struct key_t, struct stat_t, 256);
```
-----
### Python-side

The user space program has to check continuosly for map content, by spinning on infinite loop until you hit CTRL + C, which causes the exit.

```python
while True:
    try:
        timestamp = strftime('%H:%M:%S')
        print(f"Trace at: {timestamp}")
        for k, v in bpf_tabl.items():
            formatted_src   = format_ip_port(str(ip_address(k.src_ip)), int(k.src_port))
            formatted_dst   = format_ip_port(str(ip_address(k.dst_ip)), int(k.dst_port))
            formatted_stats = format_stats(int(v.bts), int(v.pkt))
            print(f"#       Session: {formatted_src} -> {formatted_dst} | {formatted_stats}")
        sleep(2)
    except KeyboardInterrupt:
        break
```

-----
### Demo

```shell
$ sudo python main.py

Hit CTRL + C to stop eBPF program :)
...
Trace at: 17:09:04
Session: 192.168.143.246:45812 ->  142.250.184.83:443   |    3.44 KB         23 packets
Session: 192.168.143.246:39396 ->     20.93.28.56:443   |    8.22 KB         42 packets
Session:     13.89.179.8:443   -> 192.168.143.246:38906 |    5.55 KB         11 packets
Session: 192.168.143.246:41402 ->     20.93.28.56:443   |  913.00  B          5 packets
Session: 192.168.143.246:35676 ->    20.189.173.7:443   |    3.67 KB         10 packets
Session: 192.168.143.246:52194 -> 108.177.119.188:5228  |    1.06 KB         16 packets
Session: 192.168.143.246:55460 ->   35.215.161.98:443   |    2.27 KB         16 packets
Session:   35.215.161.98:443   -> 192.168.143.246:55460 |    7.36 KB         15 packets
Session: 192.168.143.246:44688 ->   34.223.170.29:443   |    1.34 KB         11 packets
Session:    20.189.173.7:443   -> 192.168.143.246:35676 |    5.56 KB         12 packets
Session: 192.168.143.246:40506 ->    3.221.197.55:443   |    3.27 KB         19 packets
Session: 192.168.143.246:38906 ->     13.89.179.8:443   |    3.23 KB         12 packets
Session:    3.221.197.55:443   -> 192.168.143.246:40506 |    3.46 KB         19 packets
Session:   35.215.161.98:443   -> 192.168.143.246:55468 |    5.59 KB         10 packets
Session:     20.93.28.56:443   -> 192.168.143.246:53928 |  990.00  B         15 packets
Session:    104.18.9.150:443   -> 192.168.143.246:38688 |   22.13 KB        108 packets
Session:    13.89.178.27:443   -> 192.168.143.246:57758 |    5.45 KB         10 packets
Session:    40.79.197.34:443   -> 192.168.143.246:39018 |    5.61 KB         13 packets
Session: 192.168.143.246:51616 ->   51.104.15.252:443   |    5.34 KB         11 packets
Session:     20.93.28.56:443   -> 192.168.143.246:41402 |  396.00  B          6 packets
Session: 192.168.143.246:57758 ->    13.89.178.27:443   |    3.56 KB          9 packets
Session: 192.168.143.246:53928 ->     20.93.28.56:443   |  990.00  B         15 packets
Session: 192.168.143.246:33352 ->    13.89.178.27:443   |    2.94 KB         10 packets
Session:   40.79.141.154:443   -> 192.168.143.246:51720 |    5.55 KB         12 packets
Session: 192.168.143.246:39248 ->    74.125.11.74:443   |  680.32 KB       8833 packets
Session: 192.168.143.246:38688 ->    104.18.9.150:443   |   11.99 KB        102 packets
...
```
-----

# TCP duration

I successfully developed an eBPF program to inject into the Linux TC (Traffic Control) system, enabling me to trace TCP connections and measure how much they last, from the client sending SYN packet to the server sending FIN packet. The primary goal of this eBPF program was to monitor and gather valuable data from TCP sessions on the network. The eBPF program was attached to the TC ingress hook and the engress.

## Workflow

### C-side

Since each TCP connection is identified by the source IP address, the destination IP address, the source port and the destination port, I created ```struct key_t```

```c
struct key_t {
    unsigned int  src_ip; 
    unsigned int  src_port;
    unsigned int  dst_ip; 
    unsigned int  dst_port;
};
```

I used a BPF_HASH map, whose keys are instances of the previous C-struct, while the values are expressed by yet another C-struct called ```struct value_t```. However, the Data Plane only transfers to the Control Plane the TCP connection coordinates and the difference in nano-seconds between SYN packet and FYN packet.

```c
struct value_t {
    unsigned long SYN_timestamp;
    unsigned long FIN_timestamp;
};
BPF_HASH(connections, struct key_t, struct value_t, MAX_SIZE);

BPF_PERF_OUTPUT(output);
struct data_t {
    unsigned int  src_ip; 
    unsigned int  src_port;
    unsigned int  dst_ip; 
    unsigned int  dst_port;
    unsigned long duration_ns;
};
```
-----
### Python-side

The Control Plane listens at any event for a given amount of time before exiting

```python
print(f"Writing on statistics.dat for {duration} seconds...")
# Get the current time in seconds
start_time = time()

while (time() - start_time) < duration:
    try:
        bpf_prog.perf_buffer_poll()
    except KeyboardInterrupt:
        break
```

-----
### Demo

```shell
$ cat statistics.dat

...
192.168.143.246:60634 -> 188.184.100.182:80    | Duration: 82038937
192.168.143.246:60636 -> 188.184.100.182:80    | Duration: 76524672
192.168.143.246:60638 -> 188.184.100.182:80    | Duration: 84152228
192.168.143.246:60640 -> 188.184.100.182:80    | Duration: 72229949
192.168.143.246:60642 -> 188.184.100.182:80    | Duration: 72942887
192.168.143.246:60648 -> 188.184.100.182:80    | Duration: 74185206
192.168.143.246:60664 -> 188.184.100.182:80    | Duration: 76232049
192.168.143.246:60666 -> 188.184.100.182:80    | Duration: 80710703
192.168.143.246:60672 -> 188.184.100.182:80    | Duration: 79343380
192.168.143.246:60678 -> 188.184.100.182:80    | Duration: 70982633
192.168.143.246:60684 -> 188.184.100.182:80    | Duration: 70589822
...
```

Hist diagram result

![Screenshot](./tcp_duration/img/graph.png)

-----