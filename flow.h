/*
 * File:          flow.h
 * Institution:   FIT BUT
 * Academic year: 2022/2023
 * Course:        ISA - Network Applications and Network Administration
 * Author:        Lucie Svobodová, xsvobo1x@stud.fit.vutbr.cz
 *
 * ISA project: Generator of NetFlow data from captured network traffic
 */

#ifndef ISA_PROJECT_H
#define ISA_PROJECT_H

#include <string>
#include <pcap.h>

/**
 * Constants used in the programme.
 */


/**
 * Global variables used in the programme.
 */
char errbuf[PCAP_ERRBUF_SIZE];   // buffer used for storing error strings from pcap functions
int sigint_received;             // variable that indicates if a SIGINT signal was received
pcap_t *pcap;                    // pcap handler

/**
 * Structure used for storing command line options.
 */
typedef struct options {
    std::string file = "-";                       // name of the analyzed file
    //int netflow_collector_address;    // TODO NetFlow collector IP address - bud to nebo hostname
    std::string netflow_collector = "127.0.0.1";          // TODO NetFlow collector hostname - ukladat jako string jak adresu tak hostname, pak zkusit prevest na ipv4 adresu, pokud nejde, tak na hostname, pokud nejde tak invalid
    unsigned port;                    // NetFlow collector UDP port
    unsigned active_timer;            // active interval
    unsigned inactive_timer;          // inactive interval
    unsigned count;                   // flow-cache size
} options_t;

// NetFlow protocol struct
/*
Bytes	Contents	Description
0-1	version	NetFlow export format version number
2-3	count	Number of flows exported in this packet (1-30)
4-7	sys_uptime	Current time in milliseconds since the export device booted
8-11	unix_secs	Current count of seconds since 0000 UTC 1970
12-15	unix_nsecs	Residual nanoseconds since 0000 UTC 1970
16-19	flow_sequence	Sequence counter of total flows seen
20	engine_type	Type of flow-switching engine
21	engine_id	Slot number of the flow-switching engine
22-23	sampling_interval	First two bits hold the sampling mode; remaining 14 bits hold value of sampling interval
*/
typedef struct netflowhdr {
    u_int16_t version;
    u_int16_t count;
    u_int32_t sys_uptime;
    u_int32_t unix_sec;
    u_int32_t unix_nsecs;
    u_int32_t flow_sequence;
    u_int8_t engine_type;
    u_int8_t engine_id;
    u_int16_t sampling_interval;
} netflow_hdr;

/*
FLOW RECORD FORMAT
Bytes	Contents	Description
0-3	srcaddr	Source IP address
4-7	dstaddr	Destination IP address
8-11	nexthop	IP address of next hop router
12-13	input	SNMP index of input interface
14-15	output	SNMP index of output interface
16-19	dPkts	Packets in the flow
20-23	dOctets	Total number of Layer 3 bytes in the packets of the flow
24-27	first	SysUptime at start of flow
28-31	last	SysUptime at the time the last packet of the flow was received
32-33	srcport	TCP/UDP source port number or equivalent
34-35	dstport	TCP/UDP destination port number or equivalent
36	pad1	Unused (zero) bytes
37	tcp_flags	Cumulative OR of TCP flags
38	prot	IP protocol type (for example, TCP = 6; UDP = 17)
39	tos	IP type of service (ToS)
40-41	src_as	Autonomous system number of the source, either origin or peer
42-43	dst_as	Autonomous system number of the destination, either origin or peer
44	src_mask	Source address prefix mask bits
45	dst_mask	Destination address prefix mask bits
46-47	pad2	Unused (zero) bytes
*/
typedef struct flowformat {
    u_int32_t srcaddr;
    u_int32_t dstaddr;
    u_int32_t nexthop;
    u_int16_t input;
    u_int16_t output;
    u_int32_t dPkts;
    u_int32_t dOctets;
    u_int32_t first;
    u_int32_t last;
    u_int16_t srcport;
    u_int16_t dstport;
    u_int8_t pad1;
    u_int8_t tcp_flags;
    u_int8_t prot;
    u_int8_t tos;
    u_int16_t src_as;
    u_int16_t dst_as;
    u_int8_t src_mask;
    u_int8_t dst_mask;
    u_int16_t pad2;
} flow_format;



#endif // ISA_PROJECT_H