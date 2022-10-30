/*
 * File:          flow.cpp
 * Institution:   FIT BUT
 * Academic year: 2022/2023
 * Course:        ISA - Network Applications and Network Administration
 * Author:        Lucie Svobodová, xsvobo1x@stud.fit.vutbr.cz
 *
 * ISA project: Generator of NetFlow data from captured network traffic
 */

#include "flow.h"
#include <iostream>
#include <getopt.h>
#include <unistd.h>
#include <csignal>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <err.h>
#include <netdb.h>

/**
 * Function prints help to the standard output.
 */
void print_help() {
  printf("Generator of NetFlow data from captured network traffic.\n"
    "Usage:\n"
    "./flow [-f <file> ] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]\n"
    " -f <file>\n"
    "   - name of the analyzed file\n"
    "   - default value: STDIN\n"
    " -c <netflow_collector:port>\n"
    "   - IP address or hostname of the NetFlow collector, optionally UDP port\n"
    "   - default value: 127.0.0.1:2055\n"
    " -a <active_timer>\n"
    "   - interval (in seconds) after that the active records are exported to the collector\n"
    "   - default value: 60\n"
    " -i <inactive_timer>\n"
    "   - interval (in seconds) after that the inactive records are exported to the collector\n"
    "   - default value: 10\n"
    " -m <count>\n"
    "   - flow-cache size\n"
    "   - after hitting this size the oldest record is exported to the collector\n"
    "   - default value: 1024\n"
    "\n"
    "For more information see README or the documentation (manual.pdf).\n"
    "Author: Lucie Svobodová (xsvobo1x@stud.fit.vutbr.cz)\n"
    "ISA project, FIT BUT 2021/2022\n");
}

/**
 * Function releases all of the allocated resources.
 */
void release_resources() {
  pcap_close(pcap);           // pcap handler
  pcap_freecode(&fp);         // compiled filter
  close(sock);                // socket
  delete opts;                // options structure
}

/**
 * Function loads command line options into opts structure using getopt() function.
 * The opts structure is already initialised with default values.
 *
 * @param argc command line argument count
 * @param argv command line argument vector
 * @return 0 if successful, 1 if an error occurred, 2 if the help option is present
 */
int load_opts(int argc, char *argv[]) {
  std::string tmp;    // string used for string operations
  int res;            // variable stores the result of getopt() function
  
  // parse the command line options using getopt() function
  while ((res = getopt(argc, argv, ":f:c:a:i:m:h")) != -1) {
    switch (res) {
      case 'h':   // help (help is printed in main() -> return 2)
        return 2;
      case 'f':   // file
        // copy optarg to opts->file
        opts->file.resize(0);
        opts->file.append(optarg);
        break;
      case 'c':   // collector
        tmp.resize(260);
        tmp = optarg;
        // check address/hostname format
        opts->netflow_collector.resize(0);
        opts->netflow_collector.append(tmp.substr(0, tmp.find_last_of(":")));   // address[hostname]
        // port number
        tmp = tmp.substr(tmp.find_last_of(":") + 1);
        try {     // port: convert string to number
          if (std::stoi(tmp) >= 0)
            opts->port = std::stoi(tmp);
          else
            throw std::invalid_argument("");
        } catch (...) {
          fprintf(stderr, "invalid port number\n");
          return 1;
        }
        break;
      case 'a':   // active timer
        try {     // convert string to number
          if (std::stoi(optarg) >= 0)
            opts->active_timer = std::stoi(optarg) * 1000;    // convert seconds to milliseconds
          else
            throw std::invalid_argument("");
        } catch (...) {
          fprintf(stderr, "invalid number in option -a\n");
          return 1;
        }
        printf("-a: %u\n", opts->active_timer);
        break;
      case 'i':   // inactive timer
        try {     // convert string to number
          if (std::stoi(optarg) >= 0)
            opts->inactive_timer = std::stoi(optarg) * 1000;  // convert seconds to milliseconds
          else
            throw std::invalid_argument("");
        } catch (...) {
          fprintf(stderr, "invalid number in option -i\n");
          return 1;
        }
        break;
      case 'm':   // flow-cache size
        try {     // convert string to number
          if (std::stoi(optarg) >= 0)
            opts->count = std::stoi(optarg);
          else
            throw std::invalid_argument("");
        } catch (...) {
          fprintf(stderr, "invalid number in option -m\n");
          return 1;
        }
        break;
      default: // unknown command line option
        fprintf(stderr, "error in command line options (see -h for help)\n");
        return 1;
    }
  }
  return 0; // successful
}

// TODO remove
void print_flow (Flowformat flow) {
  struct in_addr ip_addr;
  ip_addr.s_addr = flow.srcaddr;
  std::cout << "srcaddr: " << inet_ntoa(ip_addr) << std::endl;
  ip_addr.s_addr = flow.dstaddr;
  std::cout << "srcaddr: " << inet_ntoa(ip_addr) << std::endl;
  std::cout << "sport: " << ntohs(flow.srcport) << std::endl;
  std::cout << "dport: " << ntohs(flow.dstport) << std::endl;
  //std::cout << "proto: " << flow.prot << std::endl;
  //std::cout << "tos: " << flow.tos << std::endl;
}

/**
 * Function returns current SysUptime (current time in milliseconds 
 * since the first packet was sniffed).
 * 
 * @return current SysUptime
 */
u_int32_t get_sysuptime() {
  timeval uptime;     // current SysUptime
  uptime.tv_sec = current_time.tv_sec - boot_time.tv_sec;     // seconds
  uptime.tv_usec = current_time.tv_usec - boot_time.tv_usec;  // microseconds
  if (uptime.tv_usec < 0) {
    uptime.tv_sec = uptime.tv_sec - 1;
    uptime.tv_usec = uptime.tv_usec + 1000000;
  }
  // convert to milliseconds
  return (u_int32_t)(uptime.tv_sec * 1000 + uptime.tv_usec / 1000);
}

/**
 * Function exports flow_to_export to the collector. NetFlow packet with new 
 * NetFlow header and flow_to_export as payload is created and sent as UDP packet.
 * 
 * @param flow_to_export flow record that will be exported 
 * @return 0 if successful, 1 if an error occurred
 */
int export_flow(Flowformat flow_to_export) {
  // create a netflow packet to send
  NetFlowPacket *netflowpacket = new NetFlowPacket;
  
  // create netflow header
  Netflowhdr netflowhdr;
  netflowhdr.version = htons(5);                              // NetFlow export format version number
  netflowhdr.count = htons(1);                                // number of flows exported in this packet
  netflowhdr.sys_uptime = htonl(get_sysuptime());             // current SysUptime
  netflowhdr.unix_sec = htonl(current_time.tv_sec);           // current count of seconds since 0000 UTC 1970
  netflowhdr.unix_nsecs = htonl(current_time.tv_usec * 1000); // residual nanoseconds since 0000 UTC 1970
  netflowhdr.flow_sequence = htonl(flow_seq);                 // sequence counter of total flows seen
  flow_seq++;                                                 // increment the flow sequence counter
  netflowhdr.engine_type = 0;                                 // type of flow-switching engine
  netflowhdr.engine_id = 0;                                   // slot number of the flow-switching engine
  netflowhdr.sampling_interval = 0;                           // sampling mode and interval
  
  // convert numbers in the flow record from network byte order to host byte order
  flow_to_export.first = htonl(flow_to_export.first);
  flow_to_export.last = htonl(flow_to_export.last);
  flow_to_export.nexthop = 0;
  flow_to_export.dOctets = htonl(flow_to_export.dOctets);
  flow_to_export.dPkts = htonl(flow_to_export.dPkts);

  // add the header and flowrecord to the NetFlow packet
  netflowpacket->netflowhdr = netflowhdr;
  netflowpacket->flowformat = flow_to_export;

  // send the flow to the collector
  int res = send(sock, netflowpacket, NETFLOW_PACKET_SIZE, 0);  // send data to the server
  delete netflowpacket;
  if (res != NETFLOW_PACKET_SIZE) {       // check if data was sent correctly
    fprintf(stderr, "send() failed\n");
    return 1;
  }
  return 0; // success
}

/**
 * Function exports flows for that the active or inactive timer has timed out.
 * 
 * @return 0 if successful, 1 if an error occurred
 */
int check_timers() {
  // iterate through all flows and check active and inactive timers
  auto key_value = flows.begin();
  while (key_value != flows.end()) {
    Flowformat& flowsIterator = key_value->second;
    // active and inactive timer check
    if (get_sysuptime() - flowsIterator.first > opts->active_timer
        || get_sysuptime() - flowsIterator.last > opts->inactive_timer) {
      // export flow
      if (export_flow(flowsIterator) != 0) {  // error check
        return 1;
      }
      // remove flow from flows
      key_value = flows.erase(key_value);     // update the iterator
    } else {
      key_value++;                            // increment the iterator
    }
  }
  return 0;   // success
}

/**
 * Function finds the oldest packet and returns it.
 * 
 * @return FlowKey of the oldest packet in flows
 */
FlowKey get_the_oldest_flow() {
  u_int32_t min = get_sysuptime() + 1;  // initial value for minimum
  FlowKey toRemove;                     // packet with the minimal value
  // iterate through the flows to get the oldest one
  for (auto& key_value : flows) {
    // check if the value "first" is lower than min
    if (key_value.second.first < min) {
      if (min == (get_sysuptime() + 1)) {
        // toRemove is not set yet
        min = key_value.second.first;
        toRemove = key_value.first;
        continue;
      }
      // set the current value to min and the flow to toRemove
      min = key_value.second.first;
      toRemove = key_value.first;
    } else if (key_value.second.first ==  min) {
      // check the value of nanoseconds if the seconds match
      // nanoseconds are stored in the nexthop value!
      if (key_value.second.nexthop < flows[toRemove].nexthop) {
        min = key_value.second.first;
        toRemove = key_value.first;
      }
    }
  }
  return toRemove;    // the flow to be removed from flows
}

/**
 * Function exports the oldest flow if the flow-cache is full.
 * 
 * @return 0 if successful, 1 if an error occurred
 */
int check_cache_size() {
  if (flows.size() >= opts->count) {
    // find the oldest flow
    FlowKey toRemove = get_the_oldest_flow();

    printf("REMOVING FLOW - cache size:\n");    // TODO remove
    print_flow(flows[toRemove]);                // TODO remove

    // export the flow
    if (export_flow(flows[toRemove]) != 0) {    // error check
      return 1;
    }
    // remove flow from flows
    flows.erase(toRemove);
  }
  return 0;     // success
}

/**
 * Function checks if there are any flows that should be exported. It checks the active 
 * timer, inactive timer, flow-cache and the end of TCP connection. These flows are 
 * exported and the flow passed as parameter is inserted or updated if already exists.
 * 
 * @param flow flow that should be inserted in the flows map
 */
void record_flow(Flowformat *flow) {

  // check active and inactive timers
  if (check_timers() != 0) {
    delete flow;
    release_resources();
    exit(1);
  }

  // cache size (count) check
  if (check_cache_size() != 0) {
    delete flow;
    release_resources();
    exit(1);
  }

  // create the key of the current flow
  FlowKey capturedFlow = std::make_tuple(flow->srcaddr, flow->dstaddr, flow->prot, 
                                          flow->tos, flow->srcport, flow->dstport);

  // find the current flow in flows
  if (flows.find(capturedFlow) != flows.end()) {
    // the flow already exists -> update the record
    flows[capturedFlow].dOctets += flow->dOctets;
    flows[capturedFlow].last = flow->last;
    flows[capturedFlow].dPkts++;
    flows[capturedFlow].tcp_flags |= flow->tcp_flags;
  } else {
    // the flow doesn't exist -> create new record
    flows[capturedFlow] = *flow;
  }
  
  // check for the end of the TCP connection (FIN (1) or RST (4) flag)
  if (flow->prot == TCP){
    if (((flow->tcp_flags & 1) > 0) || ((flow->tcp_flags & 4) > 0)) {
      // end of tcp connection -> export the flow
      if (export_flow(flows[capturedFlow]) != 0) {    // error check
        delete flow;
        release_resources();
        exit(1);
      }
      // remove the flow
      flows.erase(capturedFlow);
    }
  }
}

/**
 * Function saves the information about source and destination port to the flow record
 * and records the flow.
 *
 * @param packet frame data
 * @param header_length length of the IP header
 * @param flowformat flow record to be updated
 */
Flowformat *process_udp(const u_char *packet, unsigned int header_length, Flowformat *flowformat) {
  // cast frame data to udphdr structure
  struct udphdr *udp = (struct udphdr *)(packet + header_length);

  // update the flowformat record with the info found in UDP protocol
  flowformat->srcport = udp->source;      // source port
  flowformat->dstport = udp->dest;        // destination port

  // save the flow in flows and export
  record_flow(flowformat);
  return flowformat;
}

/**
 * Function saves the information source and destination port and TCP flags to the flow record
 * and records the flow.
 * 
 * @param packet frame data
 * @param header_length length of the IP header
 * @param flowformat flow record to be updated
 */
Flowformat *process_tcp(const u_char *packet, unsigned int header_length, Flowformat *flowformat) {
  // cast frame data to tcphdr structure
  struct tcphdr *tcp = (struct tcphdr *)(packet + header_length);

  // update the flowformat record with the info found in TCP protocol
  flowformat->srcport = tcp->th_sport;      // source port
  flowformat->dstport = tcp->th_dport;      // destination port
  flowformat->tcp_flags |= tcp->th_flags;   // TCP flags (cumulative OR)

  // save the flow in flows and export
  record_flow(flowformat);
  return flowformat;
}

/**
 * Function saves the information about code and type to the flow record
 * and records the flow.
 *
 * @param packet frame data
 * @param header_length length of the IP header
 * @param flowformat flow record to be updated
 */
Flowformat *process_icmp(const u_char *packet, unsigned int header_length, Flowformat *flowformat) {
  // cast to icmphdr structure
  struct icmphdr *icmp = (struct icmphdr *)(packet + header_length);

  // update the flowformat record with the info found in ICMP protocol
  flowformat->dstport = ntohs(icmp->type*256 + icmp->code);  // destination port for ICMP - code and type

  // save the flow in flows and export
  record_flow(flowformat);
  return flowformat;
}

/**
 * Function saves the information about source and destination IP address, protocol, 
 * type of service and number of bytes in the packets of the flow to the flow record,
 * resolves the protocol and calls the process_{tcp, udp, icmp}() function.
 *
 * @param packet packet data
 * @param flowformat flow record to be updated
 */
Flowformat *process_ipv4(const u_char *packet, Flowformat *flowformat) {
  struct ip *ip = (struct ip*)(packet + ETH_HEADER_SIZE);       // IP header
  // check the IP header length and IP version number
  if (ip->ip_hl * 4 < 20 || ip->ip_v != 4) {
      fprintf(stderr, "process_ipv4(): packet with invalid header sniffed\n");
      pcap_breakloop(pcap);   // return to main()
  }

  // update the flowformat record with the info found in IPv4 protocol
  flowformat->srcaddr = ip->ip_src.s_addr;  // source IPv4 address
  flowformat->dstaddr = ip->ip_dst.s_addr;  // destination IPv4 address
  flowformat->prot = ip->ip_p;              // protocol
  flowformat->tos = ip->ip_tos;             // type of service
  flowformat->dOctets = ntohs(ip->ip_len);  // number of bytes

  // check protocol type (TCP/UDP/ICMP) and record the flow
  if (ip->ip_p == TCP)
    flowformat = process_tcp(packet, ETH_HEADER_SIZE + (ip->ip_hl * 4), flowformat);
  else if (ip->ip_p == UDP)
    flowformat = process_udp(packet, ETH_HEADER_SIZE + (ip->ip_hl * 4), flowformat);
  else if (ip->ip_p == ICMPv4) {
    flowformat = process_icmp(packet, ETH_HEADER_SIZE + (ip->ip_hl * 4), flowformat);
  }
  return flowformat;
}

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
void process_frame(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  (void)args;   // args parameter is not used in this function -> remove compiler warning

  // create an ethernet header structure
  struct ether_header *eth = (struct ether_header *)(packet);

  // set boot time when processing the very first packet
  if (boot_time.tv_sec == 0) {
    boot_time.tv_sec = header->ts.tv_sec;     // seconds
    boot_time.tv_usec = header->ts.tv_usec;   // residual microseconds
  }

  // set current time
  current_time.tv_sec = header->ts.tv_sec;    // seconds
  current_time.tv_usec = header->ts.tv_usec;  // residual microseconds

  // create new flow record
  Flowformat *flowformat = new Flowformat;
  flowformat->srcaddr = 0;                    // source IPv4 address
  flowformat->dstaddr = 0;                    // destination IPv4 address
  flowformat->nexthop = header->ts.tv_usec;   // nexthop, !used here for storing microseconds - updated to 0 before export
  flowformat->input = 0;                      // SNMP index of input interface
  flowformat->output = 0;                     // SNMP index of output interface
  flowformat->dPkts = 1;                      // packets in the flow - it is the first packet currently
  flowformat->dOctets = 0;                    // total number of Layer 3 bytes in the packets of the flow
  flowformat->first = get_sysuptime();;       // SysUptime at start of flow
  flowformat->last = flowformat->first;       // SysUptime at the time the last packet of the flow was received
  flowformat->srcport = 0;                    // TCP/UDP source port number
  flowformat->dstport = 0;                    // TCP/UDP destination port number or equivalent
  flowformat->pad1 = 0;                       // unused (zero) bytes
  flowformat->tcp_flags = 0;                  // cumulative OR of TCP flags
  flowformat->prot = 0;                       // IP protocol type
  flowformat->tos = 0;                        // IP type of service (ToS)
  flowformat->src_as = 0;                     // autonomous system number of the source, either origin or peer
  flowformat->dst_as = 0;                     // autonomous system number of the destination, either origin or peer
  flowformat->src_mask = 0;                   // source address prefix mask bits
  flowformat->dst_mask = 0;                   // destination address prefix mask bits
  flowformat->pad2 = 0;                       // unused (zero) bytes
  
  // get etherType
  eth->ether_type = ntohs(eth->ether_type);

  // process the packet, store it in flows and export
  if (eth->ether_type == IPv4)
    flowformat = process_ipv4(packet, flowformat);
  delete flowformat;
}

/**
 * Function creates a filter for filtering the packets. It filters IPv4 packets (UDP, TCP and ICMP).
 *
 * @param fp pointer to the compiled filter expression
 * @return true if successful, false if an error occurred
 */
bool make_filter(struct bpf_program *fp) {
    // compile and set the filter to pcap
    if (pcap_compile(pcap, fp, "ip and (udp or tcp or icmp)", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile: invalid filter string\n");
        return false;
    }
    if (pcap_setfilter(pcap, fp) == -1) {
        fprintf(stderr, "pcap_setfilter: Error.\n");
        return false;
    }
    return true;
}

/**
 * Function handler for handling SIGINT signal. Handler breaks the loop that is
 * sniffing packets -> resources are released and the programme exits after that.
 * Global variable sigint_received indicates that the loop in main() must end.
 *
 * @param signum signal identifier required by handler function, not used
 */
void handle_signal(int signum) {
    (void)signum;           // signum is not used here -> remove compiler warning
    sigint_received = 1;    // indicates that SIGINT was received
    pcap_breakloop(pcap);   // break the sniffing loop
}

/**
 * Main function.
 * Function loads command line options and sets the signal handler.
 * Next it starts sniffing packets from the input file. It creates flows and stores
 * them in the flows map. Flows are then exported to the collector.
 * If an error occurred error message is printed to standard error (stderr).
 *
 * @param argc command line argument count
 * @param argv command line argument vector
 * @return 0 if the program ends successfully
 *         1 if an error occurred
 */
int main(int argc, char *argv[]) {
  int res;                    // variable used for storing results from functions
  sigint_received = 0;        // global variable - 0 means SIGINT signal wasn't caught
  int link_layer_header_type; // number of link-layer header type

  // create opts structure for storing command line options
  opts = new Options;
  // load command line options to the opts structure
  if ((res = load_opts(argc, argv)) != 0) {     // check error
    delete opts;        // free allocated resources
    if (res == 2) {     // 2 -> print help and exit
      print_help();
      return 0;
    }
    // error occurred - return 1
    return 1;
  }

  // create SIGINT handler
  struct sigaction sigint_handler;
  sigint_handler.sa_handler = handle_signal;
  sigemptyset(&sigint_handler.sa_mask);
  sigint_handler.sa_flags = 0;
  sigaction(SIGINT, &sigint_handler, nullptr);

  // FIXME segfault when pressing ctrl+c while loading stdin
  // open pcap file
  pcap = pcap_open_offline(opts->file.c_str(), errbuf);
  if (pcap == nullptr) {
    fprintf(stderr, "pcap_open_offline: %s", errbuf);
    delete opts;
    return 1;
  }

  // get the link-layer header type
  // list of link types: https://www.tcpdump.org/linktypes.html
  link_layer_header_type = pcap_datalink(pcap);
  if (link_layer_header_type != DLT_EN10MB) {
    fprintf(stderr, "link_layer_header err: %d\n", link_layer_header_type);
    pcap_close(pcap);
    delete opts;
    return 1;
  }

  // create a filter
  if (!make_filter(&fp)) {
    release_resources();
    return 1;
  }
  
  // create a socket for exporting the flows to the collector
  struct sockaddr_in server;        // address structure of the server
  struct hostent *servent;          // network host entry required by gethostbyname()
  memset(&server,0,sizeof(server)); // erase the server structure
  server.sin_family = AF_INET;                   

  // make DNS resolution using gethostbyname()
  if ((servent = gethostbyname(opts->netflow_collector.c_str())) == NULL) {
    fprintf(stderr,"gethostbyname() failed\n");
    release_resources();
    return 1;
  }
  memcpy(&server.sin_addr, servent->h_addr, servent->h_length); 
  server.sin_port = htons(opts->port);        // server port
  // create a client socket
  if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1) {
    fprintf(stderr,"socket() failed\n");
    release_resources();
    return 1;
  }            
  // create a connected UDP socket
  if (connect(sock, (struct sockaddr *)&server, sizeof(server))  == -1) {
    fprintf(stderr,"connect() failed\n");
    release_resources();
    return 1;
  }      
  // socket created, the flows recording and exporting can start

  // process each frame, export when necessary in export_flow()
  if (pcap_loop(pcap, -1, process_frame, NULL) != 0) {
    // fewer packets were processed
    fprintf(stderr, "pcap_loop(): %s\n", strerror(errno));
    release_resources();
    return 1;
  }

  // export the flows that remained in the flows unordered map after processing the pcap file
  while (!flows.empty() && !sigint_received) {
    // find the oldest flow
    FlowKey toRemove = get_the_oldest_flow();

    printf("REMOVING FLOW - end:\n");   // TODO remove
    print_flow(flows[toRemove]);        // TODO remove

    // export the oldest flow
    export_flow(flows[toRemove]);

    // remove it from folows
    flows.erase(toRemove);
  }

  // check for the signal handler
  if (sigint_received) {
    fprintf(stderr, "Interrupted system call\n");
    release_resources();
    return 1;
  }

  // release the resources, close the pcap and socket and return
  release_resources();
  return 0;
}
