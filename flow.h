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
 * Constants used in the program.
 */
#define ETH_HEADER_SIZE     14      // size of the Ethernet header (14 bytes)
#define NETFLOW_PACKET_SIZE 72      // number of bytes in NetFlow packet
#define IPv4                0x0800  // ether type of IPv4 
                                    // source: (https://en.wikipedia.org/wiki/EtherType)

/**
 * Enumeration used for IP protocols.
 * List of IP protocols: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
 */
enum ip_protocols {ICMPv4 = 1, TCP = 6, UDP = 17};

/**
 * Structure for NetFlow header.
 * NetFlow header: https://netflow.caligare.com/netflow_v5.htm
 * 
 * Bytes	  Contents	          Description
 * ------------------------------------------------------------------------------------------
 * 0-1	    version	            NetFlow export format version number
 * 2-3	    count	              Number of flows exported in this packet (1-30)
 * 4-7	    sys_uptime	        Current time in milliseconds since the export device booted
 * 8-11	    unix_secs	          Current count of seconds since 0000 UTC 1970
 * 12-15	  unix_nsecs	        Residual nanoseconds since 0000 UTC 1970
 * 16-19	  flow_sequence	      Sequence counter of total flows seen
 * 20	      engine_type	        Type of flow-switching engine
 * 21	      engine_id	          Slot number of the flow-switching engine
 * 22-23	  sampling_interval  	First 2 bits: sampl. mode; remaining 14 bits: sampl. interval
*/
struct Netflowhdr {
  u_int16_t version;
  u_int16_t count;
  u_int32_t sys_uptime;
  u_int32_t unix_sec;
  u_int32_t unix_nsecs;
  u_int32_t flow_sequence;
  u_int8_t  engine_type;
  u_int8_t  engine_id;
  u_int16_t sampling_interval;
};

/**
 * Structure for flow record.
 * NetFlow record: https://netflow.caligare.com/netflow_v5.htm
 * 
 * FLOW     RECORD      FORMAT
 ------------------------------------------------------------------------------------------
 * Bytes	  Contents	  Description
 * 0-3	    srcaddr	    Source IP address
 * 4-7	    dstaddr	    Destination IP address
 * 8-11	    nexthop	    IP address of next hop router
 * 12-13	  input	      SNMP index of input interface
 * 14-15	  output    	SNMP index of output interface
 * 16-19	  dPkts     	Packets in the flow
 * 20-23	  dOctets	    Total number of Layer 3 bytes in the packets of the flow
 * 24-27	  first	      SysUptime at start of flow
 * 28-31	  last	      SysUptime at the time the last packet of the flow was received
 * 32-33	  srcport   	TCP/UDP source port number or equivalent
 * 34-35	  dstport	    TCP/UDP destination port number or equivalent
 * 36	      pad1	      Unused (zero) bytes
 * 37	      tcp_flags  	Cumulative OR of TCP flags
 * 38      	prot	      IP protocol type (for example, TCP = 6; UDP = 17)
 * 39     	tos	IP      Type of service (ToS)
 * 40-41  	src_as	    Autonomous system number of the source, either origin or peer
 * 42-43  	dst_as	    Autonomous system number of the destination, either origin or peer
 * 44     	src_mask	  Source address prefix mask bits
 * 45	      dst_mask	  Destination address prefix mask bits
 * 46-47  	pad2	      Unused (zero) bytes
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
  u_int8_t  pad1;
  u_int8_t  tcp_flags;
  u_int8_t  prot;
  u_int8_t  tos;
  u_int16_t src_as;
  u_int16_t dst_as;
  u_int8_t  src_mask;
  u_int8_t  dst_mask;
  u_int16_t pad2;
};

/**
 * Structure for NetFlow packet.
 */
struct NetFlowPacket {
  Netflowhdr netflowhdr;    // NetFlow header
  Flowformat flowformat;    // Flow record
};

/**
 * Tuple used as key for flow records: (SrcIPadd, DstIPadd, Proto, ToS, SrcPort, DstPort).
 */
typedef std::tuple<u_int32_t, u_int32_t, u_int8_t, u_int8_t, u_int16_t, u_int16_t> FlowKey;

/**
 * Hash structure used in unordered_map for hashing records.
 */
struct key_hash : public std::unary_function<FlowKey, std::size_t> {
  std::size_t operator()(const FlowKey &k) const {
  u_int32_t srcaddr = std::get<0>(k);
  u_int32_t dstaddr = std::get<1>(k);

  return srcaddr ^ dstaddr ^ std::get<2>(k) ^ 
     std::get<3>(k) ^ std::get<4>(k) ^ std::get<5>(k); 
  }
};

/**
 * Structure used in unordered map for comparing records.
 */
struct key_equal : std::binary_function<FlowKey, FlowKey, bool> {
  bool operator()(FlowKey const& x, FlowKey const& y) const {
  return (std::get<0>(x) == std::get<0>(y) &&
          std::get<1>(x) == std::get<1>(y) &&
          std::get<2>(x) == std::get<2>(y) &&
          std::get<3>(x) == std::get<3>(y) &&
          std::get<4>(x) == std::get<4>(y) &&
          std::get<5>(x) == std::get<5>(y));
  }
};

/**
 * FlowsMap - unordered map used for storing flows.
 */
typedef std::unordered_map<FlowKey, Flowformat, key_hash, key_equal> FlowsMap;

/**
 * Structure used for storing command line options.
 * It is already initialised with default values.
 */
struct Options {
  std::string file = "-";                       // name of the analyzed file
  std::string netflow_collector = "127.0.0.1";  // NetFlow collector
  unsigned port = 2055;                         // NetFlow collector UDP port
  unsigned active_timer = 60000;                // active interval in milliseconds
  unsigned inactive_timer = 10000;              // inactive interval in milliseconds
  unsigned count = 1024;                        // flow-cache size
};

/**
 * Global variables used in the programme.
 */
char errbuf[PCAP_ERRBUF_SIZE];   // buffer for storing error strings from pcap functions
int sigint_received;             // variable that indicates if a SIGINT signal was received
u_int32_t flow_seq = 0;          // flow sequence
struct bpf_program fp;           // structure used for the compiled filter
timeval current_time;            // timeval for current packet time
timeval boot_time;               // timeval for boot time - time of the first packet
FlowsMap flows;                  // unordered map used for storing recorded flows
Options *opts;                   // command line options
pcap_t *pcap;                    // pcap handler
int sock;                        // socket descriptor


/*
 * Function declarations.
 */

/**
 * Function prints help to the standard output.
 */
void print_help();

/**
 * Function releases all of the allocated resources.
 */
void release_resources();

/**
 * Function loads command line options into opts structure using getopt() function.
 * The opts structure is already initialised with default values.
 *
 * @param argc command line argument count
 * @param argv command line argument vector
 * @return 0 if successful, 1 if an error occurred, 2 if the help option is present
 */
int load_opts(int argc, char *argv[]);

/**
 * Function returns current SysUptime (current time in milliseconds 
 * since the first packet was sniffed).
 * 
 * @return current SysUptime
 */
u_int32_t get_sysuptime();

/**
 * Function exports flow_to_export to the collector. NetFlow packet with new 
 * NetFlow header and flow_to_export as payload is created and sent as UDP packet.
 * 
 * @param flow_to_export flow record that will be exported 
 * @return 0 if successful, 1 if an error occurred
 */
int export_flow(Flowformat flow_to_export);

/**
 * Function exports flows for that the active or inactive timer has timed out.
 * 
 * @return 0 if successful, 1 if an error occurred
 */
int check_timers();

/**
 * Function finds the oldest packet and returns it.
 * 
 * @return FlowKey of the oldest packet in flows
 */
FlowKey get_the_oldest_flow();

/**
 * Function exports the oldest flow if the flow-cache is full.
 * 
 * @return 0 if successful, 1 if an error occurred
 */
int check_cache_size();

/**
 * Function checks if there are any flows that should be exported. It checks the active 
 * timer, inactive timer, flow-cache and the end of TCP connection. These flows are 
 * exported and the flow passed as parameter is inserted or updated if already exists.
 * 
 * @param flow flow that should be inserted in the flows map
 */
void record_flow(Flowformat *flow);

/**
 * Function saves the information about source and destination port to the flow record
 * and records the flow.
 *
 * @param packet frame data
 * @param header_length length of the IP header
 * @param flowformat flow record to be updated
 */
Flowformat *process_udp(const u_char *packet, unsigned int header_length, Flowformat *flowformat);

/**
 * Function saves the information source and destination port and TCP flags to the flow record
 * and records the flow.
 * 
 * @param packet frame data
 * @param header_length length of the IP header
 * @param flowformat flow record to be updated
 */
Flowformat *process_tcp(const u_char *packet, unsigned int header_length, Flowformat *flowformat);

/**
 * Function saves the information about code and type to the flow record
 * and records the flow.
 *
 * @param packet frame data
 * @param header_length length of the IP header
 * @param flowformat flow record to be updated
 */
Flowformat *process_icmp(const u_char *packet, unsigned int header_length, Flowformat *flowformat);

/**
 * Function saves the information about source and destination IP address, protocol, 
 * type of service and number of bytes in the packets of the flow to the flow record,
 * resolves the protocol and calls the process_{tcp, udp, icmp}() function.
 *
 * @param packet packet data
 * @param flowformat flow record to be updated
 */
Flowformat *process_ipv4(const u_char *packet, Flowformat *flowformat);

/**
 * Callback function that is called by pcap_loop() if a packet is sniffed.
 * Function processes one frame. It creates flow for the frame and calls process_ipv4()
 * function that adds additional information to the flow. Then it calls functions 
 * to save the flow in flows and takes care of the exporting to the collector.
 *
 * @param args mandatory argument of the callback function, not used in this function
 * @param header packet header structure
 * @param packet frame data
 */
void process_frame(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/**
 * Function creates a filter for filtering the packets. It filters IPv4 packets (UDP, TCP and * ICMP).
 *
 * @param fp pointer to the compiled filter expression
 * @return true if successful, false if an error occurred
 */
bool make_filter(struct bpf_program *fp);

/**
 * Function handler for handling SIGINT signal. Handler breaks the loop that is
 * sniffing packets -> resources are released and the programme exits after that.
 * Global variable sigint_received indicates that the loop in main() must end.
 *
 * @param signum signal identifier required by handler function, not used
 */
void handle_signal(int signum);

#endif // ISA_PROJECT_H