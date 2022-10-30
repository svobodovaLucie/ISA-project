## ISA - project: Generator of NetFlow data from captured network traffic
Author: Lucie Svobodová, xsvobo1x@stud.fit.vutbr.cz  
Institution: FIT BUT  
Academic year: 2022/2023  
Course: ISA - Network Applications and Network Administration

NetFlow exporter for creating flows from network traffic (.pcap files) and exporting them to the collector. NetFlow version 5 is used. The application is implemented in C++ language using the Packet Capture library ([PCAP](https://www.tcpdump.org/)).



### Build

Before building the project make sure you have installed The Packet Capture library (see [libpcap](https://www.tcpdump.org/)).  

To build the project use command:
```shell
$ make
```

To remove executable files use: 
```shell
$ make clean
```

### Usage

The NetFlow exporter supports various command line options:

```shell
$ ./flow [-f <file> ] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]
```

- `f <file>` 
  - name of the analyzed file
  - default value: STDIN
- `c <netflow_collector:port>`
  - IP address or hostname of the NetFlow collector, optionally UDP port
  - default value: 127.0.0.1:2055
- `a <active_timer>` 
  - interval (in seconds) after that the active records are exported to the collector
  - default value: 60
- `i <inactive_timer>` 
  - interval (in seconds) after that the inactive records are exported to the collector
  - default value: 10
- `m <count>` 
  - flow-cache size
  - after hitting this size the oldest record is exported to the collector
  - default value: 1024

### Usage examples
```shell
# creates flows from STDIN input with default timers and cache-size and exports them to 127.0.0.1:2055
$ ./flow

# creates flows from file 1.pcap with default timers, cache-size and collector
$ ./flow -f 1.pcap

# creates flows from file 1.pcap with default timers, maximal number of flows in the cache is 100, 
# NetFlow packets are sent to 127.0.0.1:2078
$ ./flow -f 1.pcap -c 127.0.0.1:2078 -m 100

# creates flows from STDIN input, maximal number of flows in the cache is 256, active timer is set to 50, 
# inactive timer is set to 10
$ ./flow -a 50 -i 10 -m 256
```

### Example output
Packet sniffer prints information about sniffed packets - timestamp, source and destination MAC and IP addresses,
source and destination ports if available, frame lengths, information specific for the protocols and all the frame data.  
```shell
# prints all available interfaces
$ ./ipk-sniffer -i
wlo1
lo
any
bluetooth-monitor
nflog
nfqueue
bluetooth0

# prints two packets sniffed on interface wlo1 on port 80
$ ./ipk-sniffer -i wlo1 -n 2 -p 443
2022-04-24T10:49:26.626+02.00
src MAC: 62:32:b1:09:04:6b
dst MAC: ff:ff:ff:ff:ff:ff
frame length: 56
protocol: ARP
opcode: 1 (request)
sender MAC address: 62:32:b1:09:04:6b
sender IP address: 192.168.0.17
target MAC address: 00:00:00:00:00:00
target IP address: 192.168.0.1
0x0000:  ff ff ff ff ff ff 62 32  b1 09 04 6b 06 08 00 01  ......b2 ...k.... 
0x0010:  08 00 06 04 01 00 62 32  b1 09 04 6b c0 a8 00 11  ......b2 ...k.... 
0x0020:  00 00 00 00 00 00 c0 a8  00 01 00 00 00 00 00 00  ........ ........ 
0x0030:  00 00 00 00 00 00 00 00                           ........

2022-04-24T10:49:29.392+02.00
src MAC: dc:53:7c:27:9f:48
dst MAC: c0:3c:59:cf:34:33
frame length: 93
src IP: 34.120.52.64
dst IP: 192.168.0.110
protocol: TCP
src port: 443
dst port: 43098
checksum: 0xf546
0x0000:  c0 3c 59 cf 34 33 dc 53  7c 27 9f 48 00 08 45 00  .<Y.43.S |'.H..E. 
0x0010:  00 4f 14 dd 00 00 78 06  15 fe 22 78 34 40 c0 a8  .O....x. .."x4@.. 
0x0020:  00 6e 01 bb a8 5a f8 ee  6a 1b 79 0e 61 c1 80 18  .n...Z.. j.y.a... 
0x0030:  04 1a f5 46 00 00 01 01  08 0a 5e e7 6a b8 d1 8a  ...F.... ..^.j... 
0x0040:  2b 90 17 03 03 00 16 89  fe 5c 81 6d 14 09 b7 a4  +....... .\.m.... 
0x0050:  6f 65 b5 20 8a 31 76 fb 59 92 e3 75 d8            oe. .1v. Y..u.
```

### Licence

[MIT license](https://choosealicense.com/licenses/mit/)