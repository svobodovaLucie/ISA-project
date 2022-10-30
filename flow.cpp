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
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <err.h>
#include <netdb.h>

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
  fprintf(stderr, "Releasing resources...\n");    // TODO remove
  pcap_close(pcap);           // global pcap handler
  pcap_freecode(&fp);         // compiled filter
  delete opts;             // options structure
  fprintf(stderr, "* Closing the client socket ...\n");
  close(sock);
  fprintf(stderr, "Resources released.\n");       // TODO remove
}

/**
 * Function loads command line options into opts structure using getopt_long() function.
 *
 * @return 0 if successful, 1 if an error occurred, 2 if the help option is present
 */
int load_opts(Options *opts, int argc, char *argv[])
{
  // allocate size for the netflow_collector argument
  /*
  opts->netflow_collector = (char *)calloc(260, 1); // max number of characters for a hostname is 253 + port 5 chars
  if (opts->netflow_collector == std::nullptr)
  {
    // TODO error
    return 1;
  }
  */
  std::string tmp;
  //int tmp_port;
  //  the struct is already initialised with the default values
  
  // define variables used in getopt_long() function
  opterr = 0; // suppress default error messages
  // parse the command line options using getopt() function
  int res;
  while ((res = getopt(argc, argv, ":f:c:a:i:m:h")) != -1) { // TODO port nse nezapisuje jako p, ale je soucasti c za :xxxx
    // while ((res = getopt_long(argc, argv, optstring, longopts, &longindex)) != -1) {
    //  TODO check aby neproslo napr. -m 76565y (ted projde)
    switch (res) {
    case 'h': // help
      // help will be printed in main() - returns 2
      return 2;
    case 'f': // file
      // copy optarg to opts->file
      opts->file.resize(0);
      opts->file.append(optarg);

      std::cout << "f: " << opts->file << std::endl;
      break;
    case 'c':
      tmp.resize(260);
      tmp = optarg;
      // check address/hostname format
      opts->netflow_collector.resize(0);
      opts->netflow_collector.append(tmp.substr(0, tmp.find_last_of(":")));   // address[hostname]
      // port number
      tmp = tmp.substr(tmp.find_last_of(":") + 1);
      try {
        if (std::stoi(tmp) >= 0)
          opts->port = std::stoi(tmp);
        else
          throw std::invalid_argument("");
      } catch (...) {
        fprintf(stderr, "invalid port number\n");
        delete opts;  // FIXME release_resources
        return 1;
      }
      
      std::cout << "opts->netflow: " << opts->netflow_collector << "\n";
      std::cout << "opts->port: " << opts->port << "\n";

      break;
    case 'a':
      try {
        if (std::stoi(optarg) >= 0)
          opts->active_timer = std::stoi(optarg) * 1000;
        else
          throw std::invalid_argument("");
      } catch (...) {
        fprintf(stderr, "invalid number in option -a\n");
        delete opts;  // FIXME release_resources
        return 1;
      }
      printf("-a: %u\n", opts->active_timer);
      break;
    case 'i':
      try {
        if (std::stoi(optarg) >= 0)
          opts->inactive_timer = std::stoi(optarg) * 1000;
        else
          throw std::invalid_argument("");
      } catch (...) {
        fprintf(stderr, "invalid number in option -i\n");
        delete opts;  // FIXME release_resources
        return 1;
      }
      printf("-i: %u\n", opts->inactive_timer);
      break;
    case 'm': //
      try {
        if (std::stoi(optarg) >= 0)
          opts->count = std::stoi(optarg);
        else
          throw std::invalid_argument("");
      } catch (...) {
        fprintf(stderr, "invalid number in command line options\n");
        delete opts;  // FIXME release_resources
        return 1;
      }
      printf("-m: %u\n", opts->count);
      break;
    default: // unknown command line option
      printf("error in command line options (see -h or --help for help)\n");
      delete opts;  // FIXME release_resources
      return 1;
    }
  }

  return 0; // successful
}

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

u_int32_t get_sysuptime() {
  timeval uptime;
  uptime.tv_sec = current_time.tv_sec - boot_time.tv_sec;
  uptime.tv_usec = current_time.tv_usec - boot_time.tv_usec;
  if (uptime.tv_usec < 0) {
    uptime.tv_sec = uptime.tv_sec - 1;
    uptime.tv_usec = uptime.tv_usec + 1000000;
  }
  
  return (u_int32_t)(uptime.tv_sec * 1000 + uptime.tv_usec / 1000);
}

int export_flow(Flowformat flow_to_export) {
  // export flow
  // create a netflow packet to send
  NetFlowPacket *netflowpacket = new NetFlowPacket;
  // create netflow header
  Netflowhdr netflowhdr;
  netflowhdr.version = htons(5);        // yes
  netflowhdr.count = htons(1);          // yes
  netflowhdr.sys_uptime = htonl(get_sysuptime());            // milliseconds - okay? + is htonl okay? - should be probably first not last
  netflowhdr.unix_sec = htonl(current_time.tv_sec);   // FIXME spatne - musi to byt z first!!!
  netflowhdr.unix_nsecs = htonl(current_time.tv_usec * 1000);            // yes
  netflowhdr.flow_sequence = htonl(flow_seq);  // yes - cislo flow, inkrementace pri generovani flows
  flow_seq++;                           
  netflowhdr.engine_type = 0;           // ?
  netflowhdr.engine_id = 0;             // ?
  netflowhdr.sampling_interval = 0;     // ?
  // add the flowrecord data to the packet
  netflowpacket->netflowhdr = netflowhdr;
  // TODO maybe Segfault
  flow_to_export.first = htonl(flow_to_export.first); // TODO check
  flow_to_export.last = htonl(flow_to_export.last); // TODO check
  flow_to_export.nexthop = 0;
  //flow_to_export.first = 0;
  // TODO htons and htonl where necessary
  flow_to_export.dOctets = htonl(flow_to_export.dOctets);
  flow_to_export.dPkts = htonl(flow_to_export.dPkts);
  netflowpacket->flowformat = flow_to_export;    // do I have to memcpy or sth like that?
  // send the flow
  int msg_size = NETFLOW_PACKET_SIZE;

  int i = send(sock,netflowpacket, msg_size,0);     // send data to the server
  
  delete netflowpacket;
  if (i == -1) {                    // check if data was sent correctly
    //err(1,"send() failed");       // TODO memleak in the err() function - not releasing the resources
    fprintf(stderr, "send() failed\n");
    release_resources();            // TODO memleak - flow_to_export is not deleted
    exit(1);
  } else if (i != msg_size) {                    // check if data was sent correctly
    //err(1,"send(): buffer written partially");       // TODO memleak in the err() function - not releasing the resources
    fprintf(stderr, "send() failed\n");
    release_resources();            // TODO memleak - flow_to_export is not deleted
    exit(1);
  }
  //else
  //  printf("msg sent successfully\n");

  return 0; // success ir return flow or sth
}

/**
 * @brief FIXME return FlowKey, FlowRecord or int? Fro error reporting etc.
 * 
 * @return int 
 */
int record_flow(Flowformat *flow) {
  // iterate through all flows and check active and inactive timers
  auto key_value = flows.begin();
  while (key_value != flows.end()) {
    Flowformat& flowsIterator = key_value->second;
    // active and inactive timer check + export
    if (get_sysuptime() - flowsIterator.first > opts->active_timer /* TODO check seconds and type */
        || get_sysuptime() - flowsIterator.last > opts->inactive_timer) {
      // export flow
      export_flow(flowsIterator);
      // remove flow from flows
      key_value = flows.erase(key_value); // do I have to delete the record somehow with delete?
    } else {
      key_value++;
    }
  }

  // cache size (count) check + export
  if (flows.size() >= opts->count) {
    u_int32_t min = get_sysuptime() + 1;  // FIXME: use now() function for getting the current time - it will be the maximum every time or use the time of the first packet
    FlowKey toRemove;           // packet with the minimal value -> the one to be removed
    // iterate through the flows to get the oldest one
    for (auto& key_value : flows) {
      if (key_value.second.first < min) {
        if (min == (get_sysuptime() + 1)) {
          // toRemove is not set yet
          min = key_value.second.first;
          toRemove = key_value.first;
          continue;
        }
        min = key_value.second.first;
        toRemove = key_value.first;
      } else if (key_value.second.first ==  min) {
        if (key_value.second.nexthop < flows[toRemove].nexthop) {
          min = key_value.second.first;
          toRemove = key_value.first;
        }
      }
    }

    printf("REMOVING FLOW - cache size:\n");
    print_flow(flows[toRemove]);

    // export the flow
    export_flow(flows[toRemove]);

    // erase it
    flows.erase(toRemove);
  }

  // key of the current flow
  FlowKey capturedFlow = std::make_tuple(flow->srcaddr, flow->dstaddr, flow->prot, 
                                          flow->tos, flow->srcport, flow->dstport);

  // find the current flow in the flows
  if (flows.find(capturedFlow) != flows.end()) {    // if exists then update the record
    flows[capturedFlow].dOctets += flow->dOctets;
    flows[capturedFlow].last = flow->last;
    flows[capturedFlow].dPkts++;
    flows[capturedFlow].tcp_flags |= flow->tcp_flags;
  } else {      // if doesn't exist then create new record
    flows[capturedFlow] = *flow;
  }
  
  // check for the end of the TCP connection (FIN (1) or RST (4) flag)
  // if check tcp fin flag     
  if (flow->prot == TCP){
    if (((flow->tcp_flags & 1) > 0) || ((flow->tcp_flags & 4) > 0)) {
      // end of tcp connection -> export the flow
      export_flow(flows[capturedFlow]);
      // remove the flow
      flows.erase(capturedFlow);
    }
  }

  return 0; // success
}

/**
 * Function prints more information about UDP packet. It prints source
 * and destination ports, checksum and the frame data;
 *
 * @param header packet header
 * @param packet frame data
 * @param header_length length of the IP header
 */
Flowformat *process_udp(struct pcap_pkthdr header, const u_char *packet, unsigned int header_length, Flowformat *flowformat) {
  (void)header; // TODO remove the parameter header

  // cast frame data to udphdr structure
  struct udphdr *udp = (struct udphdr *)(packet + header_length);

  // update the flowformat record with the info found in ipv4 protocol
  flowformat->input = 0;                                   // no
  flowformat->output = 0;                                  // no
  flowformat->srcport = udp->source;
  flowformat->dstport = udp->dest;

  record_flow(flowformat);

  return flowformat;
}

/**
 * Function prints more information about TCP packet. It prints source
 * and destination ports, checksum and frame data.
 *
 * @param header packet header
 * @param packet frame data
 * @param header_length length of the IP header
 */
Flowformat *process_tcp(struct pcap_pkthdr header, const u_char *packet, unsigned int header_length, Flowformat *flowformat) {
  (void)header; // TODO remove the parameter header

  // cast frame data to tcphdr structure
  struct tcphdr *tcp = (struct tcphdr *)(packet + header_length);

  // update the flowformat record with the info found in ipv4 protocol
  flowformat->input = 0;                                   // no
  flowformat->output = 0;                                  // no
  flowformat->srcport = tcp->th_sport; //htons(std::get<4>(capturedFlow));  // yes
  flowformat->dstport = tcp->th_dport; //htons(std::get<5>(capturedFlow));  // yes
  flowformat->tcp_flags |= tcp->th_flags;                               // yes - cumulative OR

  record_flow(flowformat);
  return flowformat;
}

/**
 * Function prints more information about ICMP packet - type, code, checksum
 * and the frame data.
 *
 * @param header packet header
 * @param packet frame data
 * @param header_length length of the IP header
 */
Flowformat *process_icmp(struct pcap_pkthdr header, const u_char *packet, unsigned int header_length, Flowformat *flowformat) {
  (void)header; // TODO remove the parameter header

  // cast to icmphdr structure
  struct icmphdr *icmp = (struct icmphdr *)(packet + header_length);

  // update the flowformat record with the info found in ipv4 protocol
  flowformat->input = 0;                                   // no
  flowformat->output = 0;                                  // no
  flowformat->dstport = ntohs(icmp->type*256 + icmp->code);        // FIXME ntohs? or not

  record_flow(flowformat);

  return flowformat;
}

/**
 * Function processes IPv4 packet. It checks the header length and IP version,
 * prints IP addresses and call appropriate function to print more information.
 *
 * @param header packet header
 * @param packet packet data
 */
Flowformat *process_ipv4(struct pcap_pkthdr header, const u_char *packet, Flowformat *flowformat) {
  struct ip *ip = (struct ip*)(packet + ETH_HEADER_SIZE);       // IP header
  // check the IP header length and IP version number
  if (ip->ip_hl * 4 < 20 || ip->ip_v != 4) {
      printf("packet with invalid header catched\n");
      pcap_breakloop(pcap);
      // TODO return NULL;
      exit(1);  // FIXME remove!!!
  }

  // update the flowformat record with the info found in ipv4 protocol
  flowformat->srcaddr = ip->ip_src.s_addr;  // yes
  flowformat->dstaddr = ip->ip_dst.s_addr;  // yes
  flowformat->prot = ip->ip_p;            // yes
  flowformat->tos = ip->ip_tos;             // yes
  flowformat->dOctets = ntohs(ip->ip_len);

  // check protocol type (TCP/UDP/ICMP) and print more information
  if (ip->ip_p == TCP)
    flowformat = process_tcp(header, packet, ETH_HEADER_SIZE + (ip->ip_hl * 4), flowformat);
  else if (ip->ip_p == UDP)
    flowformat = process_udp(header, packet, ETH_HEADER_SIZE + (ip->ip_hl * 4), flowformat);
  else if (ip->ip_p == ICMPv4) {
    flowformat = process_icmp(header, packet, ETH_HEADER_SIZE + (ip->ip_hl * 4), flowformat);
  }

  return flowformat;
}

/**
 * Callback function that is called by pcap_loop() if a packet is sniffed.
 * Function processes one frame. It prints RFC3339 timestamp, source MAC address,
 * destination MAC address and frame length. By the EtherType is decided what
 * protocol should be processed and appropriate function is called to print
 * more information about the packet.
 *
 * @param args mandatory argument of the callback function, not used in this function
 * @param header packet header structure
 * @param packet frame data
 */
void process_frame(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  (void)args;     // args parameter is not used in this function -> remove compiler warning

  // create an ethernet header structure
  struct ether_header *eth = (struct ether_header *)(packet);

  if (boot_time.tv_sec == 0) {
    //it is the first packet now -> set boot time
    boot_time.tv_sec = header->ts.tv_sec;
    boot_time.tv_usec = header->ts.tv_usec;
  }

  // set current time
  current_time.tv_sec = header->ts.tv_sec;          // seconds
  current_time.tv_usec = header->ts.tv_usec;        // residual microseconds

  Flowformat *flowformat = new Flowformat;

  // add the time and other useful information to the flowrecord
  flowformat->srcaddr = 0;  // yes
  flowformat->dstaddr = 0; // std::get<1>(capturedFlow).s_addr;  // yes
  flowformat->nexthop = header->ts.tv_usec;   // just to store microsec for exporting          // no OK
  flowformat->input = 0;                                   // no
  flowformat->output = 0;                                  // no
  flowformat->dPkts = 1;                            // yes - one packet currently
  flowformat->dOctets = 0;                                 // yes - suma header length - Layer 3 bytes in packets - which bytes are computed?
  // save times without htonl and htonl() them before export
  flowformat->first = get_sysuptime();;            // yes - SysUptime at start of flow -> time in the first packet of the flow hopefully? FIXME                               // no OK
  flowformat->last = flowformat->first;             // yes - same as .first -> if this the only packet I think this is right
  flowformat->srcport = 0; //htons(std::get<4>(capturedFlow));  // yes
  flowformat->dstport = 0; //htons(std::get<5>(capturedFlow));  // yes
  flowformat->pad1 = 0;                                    // no OK
  flowformat->tcp_flags = 0;                               // yes - cumulative OR
  flowformat->prot = 0; //std::get<2>(capturedFlow);            // yes
  flowformat->tos = 0; //std::get<3>(capturedFlow);             // yes
  flowformat->src_as = 0;                                  // no OK
  flowformat->dst_as = 0;                                  // no OK
  flowformat->src_mask = 0;                               // yes - 32?
  flowformat->dst_mask = 0;                               // yes - 32?
  flowformat->pad2 = 0;                                    // no OK
  
  // get etherType
  eth->ether_type = ntohs(eth->ether_type);
  // process and print the packet
  if (eth->ether_type == IPv4)
    flowformat = process_ipv4(*header, packet, flowformat);
  else if (eth->ether_type == IPv6) {
    fprintf(stderr, "---- IPv6 ----\n");  // TODO remove
    return;
  }

  // adding and wexporting netflows done in process_tcp/udp/icmp functions.
  delete flowformat;
}


/**
 * Function creates a filter for filtering the packets. How the filter is created
 * depends on command line arguments (stored in opts structure).
 *
 * @param opts structure that stores command line options
 * @param fp pointer to the compiled filter expression
 * @return true if successful, false if an error occurred
 */
bool make_filter(struct bpf_program *fp) {
    // compile and set the filter to pcap
    // FIXME not sure about icmp6
    // FIXME check if the ip AND () is okay (ip should filter only ipv4 addresses)
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



int main(int argc, char *argv[]) {
  int res;                    // variable used for storing results from functions
  sigint_received = 0;        // global variable - 0 means SIGINT signal wasn't caught
  int link_layer_header_type; // number of link-layer header type
  //boot_time = 0;

  // create opts structure for storing command line options
  opts = new Options;
  // load command line options to the opts structure
  if ((res = load_opts(opts, argc, argv)) != 0) {
    // free allocated resources
    // if help was printed - return 0
    if (res == 2) {
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

  // main loop
  // FIXME segfault when pressing ctrl+c while loading stdin
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
    printf("link_layer_header err: %d\n", link_layer_header_type);
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
  struct sockaddr_in server;   // address structure of the server
  struct hostent *servent;         // network host entry required by gethostbyname()

  memset(&server,0,sizeof(server)); // erase the server structure
  server.sin_family = AF_INET;                   

  // make DNS resolution of the first parameter using gethostbyname()
  if ((servent = gethostbyname(opts->netflow_collector.c_str())) == NULL) // check the first parameter
    errx(1,"gethostbyname() failed\n");

  // copy the first parameter to the server.sin_addr structure
  memcpy(&server.sin_addr,servent->h_addr,servent->h_length); 

  server.sin_port = htons(opts->port);        // server port (network byte order)
   
  if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)   //create a client socket
    err(1,"socket() failed\n");

  printf("* Creating a connected UDP socket using connect()\n");                
  // create a connected UDP socket
  if (connect(sock, (struct sockaddr *)&server, sizeof(server))  == -1)
    err(1, "connect() failed");

  // socket created, the flows recording and exporting can start
  // process each frame, export when necessary in export_flow()
  if (pcap_loop(pcap, -1, process_frame, NULL) != 0) {
      // fewer packets were processed
      fprintf(stderr, "pcap_loop: %s\n", strerror(errno));
  }

  // export the flows that remained in the flows unordered map after processing the pcap file
  while (!flows.empty()) {
    // find minimum
    u_int32_t min = get_sysuptime() + 1;
    FlowKey toRemove;           // packet with the minimal value -> the one to be removed
    // iterate through tfhe flows to get the oldest one
    for (auto& key_value : flows) {
      if (key_value.second.first < min) {
        if (min == (get_sysuptime() + 1)) {
          // toRemove is not set yet
          min = key_value.second.first;
          toRemove = key_value.first;
          continue;
        }
        min = key_value.second.first;
        toRemove = key_value.first;
      } else if (key_value.second.first ==  min) {
        if (key_value.second.nexthop < flows[toRemove].nexthop) {
          min = key_value.second.first;
          toRemove = key_value.first;
        }
      }
    }
    printf("REMOVING FLOW - end:\n");
    print_flow(flows[toRemove]);

    // export the flow
    export_flow(flows[toRemove]);

    // erase it
    flows.erase(toRemove);
  }

  // release the resources, close the pcap and socket and return
  release_resources();
  return 0;
}