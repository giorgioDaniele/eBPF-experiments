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