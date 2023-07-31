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

The Control Plane listens indefinetely until you hit CTRL + C.

```python
try:
    while True:
        bpf_prog.perf_buffer_poll()
except KeyboardInterrupt:
    pass
```

-----
### Demo

```shell
$ cat statistics.dat

...
192.168.143.246:43052 ->   137.226.34.46:80    | Duration: 0.244123127  s
192.168.143.246:40284 -> 130.192.181.230:443   | Duration: 5.219493615  s
192.168.143.246:44750 ->   130.192.95.68:443   | Duration: 9.804791219  s
192.168.143.246:44740 ->   130.192.95.68:443   | Duration: 10.108454423 s
192.168.143.246:44722 ->   130.192.95.68:443   | Duration: 16.002086138 s
192.168.143.246:33726 ->  130.192.55.240:443   | Duration: 6.504344594  s
192.168.143.246:33722 ->  130.192.55.240:443   | Duration: 7.714727185  s
...
```

Hist diagram result

![Screenshot](./tcp_duration/img/graph.png)

-----