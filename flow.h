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

#define __FAVOR_BSD

#include <string>
#include <pcap.h>
#include <tuple>
#include <map>
#include <unordered_map>

/**
 * Constants used in the programme.
 */
#define ETH_HEADER_SIZE   14     // size of the Ethernet header (14 bytes)
#define IPV6_HEADER_SIZE  40     // size of the IPv6 header (40 bytes)
#define MAX_TIMESTAMP_LEN 22     // max length of timestamp buffer used
#define FRAME_PRINT_LEN   16     // length of the data to be printed on one line

/**
 * Global variables used in the programme.
 */
char errbuf[PCAP_ERRBUF_SIZE];   // buffer used for storing error strings from pcap functions
int sigint_received;             // variable that indicates if a SIGINT signal was received
pcap_t *pcap;                    // pcap handler
u_int32_t flow_seq = 0;          // flow sequence
// Options *opts;
int sock;                        // socket descriptor
struct bpf_program fp;  // structure used for the compiled filter

/**
 * Enumeration used for ether types.
 * List of ether types: https://en.wikipedia.org/wiki/EtherType
 */
enum ether_types {IPv4 = 0x0800, ARP = 0x0806, IPv6 = 0x86DD};

/**
 * Enumeration used for IP protocols.
 * List of IP protocols: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
 */
enum ip_protocols {ICMPv4 = 1, TCP = 6, UDP = 17, ICMPv6 = 58, NO_NEXT_HEADER = 59};


/**
 * Structure used for storing command line options.
 */
struct Options {
    std::string file = "-";                       // name of the analyzed file
    //int netflow_collector_address;    // TODO NetFlow collector IP address - bud to nebo hostname
    std::string netflow_collector = "127.0.0.1";          // TODO NetFlow collector hostname - ukladat jako string jak adresu tak hostname, pak zkusit prevest na ipv4 adresu, pokud nejde, tak na hostname, pokud nejde tak invalid
    unsigned port = 2055;                    // NetFlow collector UDP port
    unsigned active_timer = 60;            // active interval
    unsigned inactive_timer = 10;          // inactive interval
    unsigned count = 1024;                   // flow-cache size
};

Options *opts;                   // command line options

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
struct Netflowhdr {
    u_int16_t version;
    u_int16_t count;
    u_int32_t sys_uptime;
    u_int32_t unix_sec;
    u_int32_t unix_nsecs;
    u_int32_t flow_sequence;
    u_int8_t engine_type;
    u_int8_t engine_id;
    u_int16_t sampling_interval;
};

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
struct Flowformat {
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
};

struct NetFlowPacket {
    Netflowhdr netflowhdr;
    Flowformat flowformat;
};

/*
 * Tuple for netflow record used as a key in map.
 * FIXME: SrcIf - source interface - how to get/store it?
 * SrcIPadd, DstIPadd, Proto, ToS, SrcPort, DstPort
 */
typedef std::tuple<u_int32_t, u_int32_t, u_int8_t, u_int8_t, u_int16_t, u_int16_t> FlowKey;

struct key_hash : public std::unary_function<FlowKey, std::size_t> {
    std::size_t operator()(const FlowKey &k) const {
        u_int32_t srcaddr = std::get<0>(k);
        u_int32_t dstaddr = std::get<1>(k);

        return srcaddr ^ dstaddr ^ std::get<2>(k) ^ 
               std::get<3>(k) ^ std::get<4>(k) ^ std::get<5>(k); 
    }
};

struct key_equal : std::binary_function<FlowKey, FlowKey, bool> {
    bool operator()(FlowKey const& x, FlowKey const& y) const {
        return ( std::get<0>(x) == std::get<0>(y) &&
                 std::get<1>(x) == std::get<1>(y) &&
                 std::get<2>(x) == std::get<2>(y) &&
                 std::get<3>(x) == std::get<3>(y) &&
                 std::get<4>(x) == std::get<4>(y) &&
                 std::get<5>(x) == std::get<5>(y) );
    }
};

// TODO
typedef std::unordered_map<FlowKey, Flowformat, key_hash, key_equal> FlowsMap;

FlowsMap flows;

#endif // ISA_PROJECT_H