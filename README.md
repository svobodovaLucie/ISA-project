## ISA - project: Generator of NetFlow data from captured network traffic
Author: Lucie Svobodová, xsvobo1x@stud.fit.vutbr.cz  
Institution: FIT BUT  
Academic year: 2022/2023  
Course: ISA - Network Applications and Network Administration

Evaluation: 20/20 points  

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

# creates flows from STDIN input, maximal number of flows in the cache is 256, active timer is set to 50 s, 
# inactive timer is set to 10 s
$ ./flow -a 50 -i 10 -m 256
```

### Example output
Exported flows can be printed by various programs, e.g. [nfdump](https://nfdump.sourceforge.net/). 
Packet sniffer prints information about sniffed packets - timestamp, source and destination MAC and IP addresses,
source and destination ports if available, frame lengths, information specific for the protocols and all the frame data.  
```shell
# ./flow -f pcaps/big.pcap -c 127.0.0.1:2787 -i 5 -a 10 -m 10
# flows exported by the command above are stored in nfcapd.202210300215 file
$ nfdump -r nfcapd.202210300215     # output from nfdump
Date first seen          Event  XEvent Proto      Src IP Addr:Port          Dst IP Addr:Port     X-Src IP Addr:Port        X-Dst IP Addr:Port   In Byte Out Byte
2022-10-06 13:55:27.120 INVALID  Ignore UDP     100.64.205.216:54915 ->   100.64.223.255:54915          0.0.0.0:0     ->          0.0.0.0:0          582        0
2022-10-06 13:55:27.266 INVALID  Ignore TCP     100.64.208.103:40988 ->     147.229.2.90:443            0.0.0.0:0     ->          0.0.0.0:0          279        0
2022-10-06 13:55:27.269 INVALID  Ignore TCP       147.229.2.90:443   ->   100.64.208.103:40988          0.0.0.0:0     ->          0.0.0.0:0         1176        0
2022-10-06 13:55:27.424 INVALID  Ignore UDP     100.64.192.180:54915 ->   100.64.223.255:54915          0.0.0.0:0     ->          0.0.0.0:0          291        0
2022-10-06 13:55:27.736 INVALID  Ignore UDP     100.64.199.189:57621 ->   100.64.223.255:57621          0.0.0.0:0     ->          0.0.0.0:0           72        0
Summary: total flows: 5, total bytes: 2400, total packets: 16
Time window: 2022-10-06 13:55:27 - 2022-10-06 13:55:28
Total flows processed: 5, Blocks skipped: 0
```

### Licence

[MIT license](https://choosealicense.com/licenses/mit/)
