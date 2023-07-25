# TCP Logger

The eBPF program is injected into the kernel to intercept network traffic. It aims at grouping packets by source IP address, destination IP address, source TCP port, and destination TCP port. For each TCP connection, the eBPF routine updates the number of bytes exchanged within such connection and the number of packets.
## Workflow

### C-side

The hash map key is defined as a C structure.

```c
struct key_t {
    // Layer 3
    unsigned int src_ip;
    unsigned int dst_ip;
    // Layer 4
    unsigned short src_port;
    unsigned short dst_port;
};
```

The hash map value is also defined as a C structure.

```c
struct value_t{
    // Statistics
    unsigned long bytes;
    unsigned long packets;
    // Lock
    struct bpf_spin_lock lock;
};
```
Packet inspection is driven by two main functions: **move_on()** and **is_okay()**. Because of the eBPF verifier, whenever I am about to access a memory location, I have to test packet buffer boundaries. Moreover, to make the code more modular I would like to split overall logic in functions. However, it is not permitted due to the tiny eBPF stack size (512 bytes). So, I can only use **__always_inline** functions, that is a function whose stack frame replaces the caller one.

```c
static __always_inline void *move_on(void *pointer, unsigned char offset) {
    return pointer + offset;
}
static __always_inline int is_okay(void *pointer, unsigned char offset, void *end) {
    if (pointer + offset <= end)
        return 1; // True
    return 0;     // False
}
```

Packet processing is usually performed on different cores. **BPF_HASH()** creates a shared memory area across CPU cores. Because of that, before updating a map, I have to synchonize map access.

```c
struct value_t *value  = connections.lookup_or_try_init(&key, &new_value);
if(value != NULL) {
    // Notice that my program is running on a multi-core system, so I do not 
    // care about the physical core which processes the packet, I just to make
    // my map consistent, by updating it synchronously. So, I use a spin lock
    bpf_spin_lock(&value->lock);
    value->bytes    = value->bytes   +  size;
    value->packets  = value->packets +  1;
    bpf_spin_unlock(&value->lock);
}
bpf_trace_printk("Done at %lu, size = %u!", bpf_ktime_get_ns(), size);
```
-----
### Python-side

The user space program checks continuosly the map and display it on standard output 

```python
while True:
    try:
        print_map()
    except KeyboardInterrupt:
        break
...
print(f"-- [TCP connection ] --")
print(f"[IP]\nSrc IP Address: {src_ip}\nDst IP Address: {dst_ip}\n[TCP]\nSrc Port: {src_port}\nDst Port: {dst_port}")
print(f"        Bytes   = {bytes}\n        Packets = {packets}")
print(f"-----------------------")

```

-----
### Demo

```shell
$ sudo python main.py

...

-- [TCP connection ] --
[IP]
Src IP Address: 173.194.182.137
Dst IP Address: 192.168.143.246
[TCP]
Src Port: 443
Dst Port: 50180
        Bytes   = 1398665
        Packets = 965
-----------------------
-- [TCP connection ] --
[IP]
Src IP Address: 140.82.113.25
Dst IP Address: 192.168.143.246
[TCP]
Src Port: 443
Dst Port: 59762
        Bytes   = 224
        Packets = 3
-----------------------

...

```
-----