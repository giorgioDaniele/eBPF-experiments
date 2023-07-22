# eBPF-experiments

![Linux](https://img.shields.io/badge/platform-linux-yellow)
![Python](https://img.shields.io/badge/language-python-green)

A collection of experiments with eBPF, a technology that can run sandboxed programs in a privileged context such as the operating system kernel. This collection proposes some use cases for networking purposes. Each
project is powered by [bcc](https://github.com/iovisor/bcc/tree/master) toolkit.


## Table of Contents

- Connections Log
- Connections Tracker
- HTTP Inspector


## Connections Log
This project aims to evaluate the duration of TCP connections created by the host to download data over the network.

```Shell
$ cd connections_log
$ sudo python3 main.py
...
### [ Connection ] ###
Src IP: 212.102.55.130:443, Dst IP: 192.168.143.246:53734
    Duration: 2.70 s

### [ Connection ] ###
Src IP: 216.58.204.131:443, Dst IP: 192.168.143.246:55650
    Duration: 73.81 s

### [ Connection ] ###
Src IP: 18.159.254.57:80, Dst IP: 192.168.143.246:54322
    Duration: 138.09 ms
```

## Connections Tracker
This project aims to evaluate the duration of how many packets and bytes are exchanged per each TCP connection.

```Shell
$ cd connections_tracker
$ sudo python3 main.py -i <ifname> -p <period>
---------------------------------------------------------------
 Connections report, [2023-07-22 09:56:24]: 
|    Source      IP:   140.82.121.4 (Remote server) 
|    Destination IP:   192.168.143.246 (My host)       
|    Source      Port: 443                              
|    Destination Port: 41854                              
|        Bytes:   90                                     
|        Packets: 1                                   
|    Source      IP:   188.42.191.196 (Remote server) 
|    Destination IP:   192.168.143.246 (My host)       
|    Source      Port: 443                              
|    Destination Port: 45244                              
|        Bytes:   66                                     
|        Packets: 1
----------------------------------------------------------------
```

## HTTP Inspector
This project aims to inspect HTTP traffic.

```Shell
$ cd connections_log
$ sudo python3 main.py

Packet  Length: 956
Header  Lenght: 66
HTTP/1.1 200 OK
Date: Fri, 21 Jul 2023 12:42:56 GMT
Server: Apache
Last-Modified: Wed, 05 Feb 2014 16:00:31 GMT
ETag: "286-4f1aadb3105c0"
Accept-Ranges: bytes
Content-Type: text/html
Content-Length: 646
Connection: keep-alive

<html><head></head><body><header>
<title>http://info.cern.ch</title>
</header>

<h1>http://info.cern.ch - home of the first website</h1>
<p>From here you can:</p>
<ul>
<li><a href="http://info.cern.ch/hypertext/WWW/TheProject.html">Browse the first website</a></li>
<li><a href="http://line-mode.cern.ch/www/hypertext/WWW/TheProject.html">Browse the first website using the line-mode browser simulator</a></li>
<li><a href="http://home.web.cern.ch/topics/birth-web">Learn about the birth of the web</a></li>
<li><a href="http://home.web.cern.ch/about">Learn about CERN, the physics laboratory where the web was born</a></li>
</ul>
</body></html>
```