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
 *
 * @param opts structure that stores command line options
 * @param fp compiled filter
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
          opts->active_timer = std::stoi(optarg);
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
          opts->inactive_timer = std::stoi(optarg);
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

// TODO remove
void printf_flows() {
  std::cout << "flows:\n" << "=============" << std::endl;
  for (auto& keyValue : flows) {
    auto &key = keyValue.first;
    //Flowformat& value = kv.second;
    //std::cout << "src IP  : " << inet_ntoa(std::get<0>(key)) << ", ";    // src IP
    //std::cout << "dst IP  : " << inet_ntoa(std::get<1>(key)) << ", " << std::endl;    // dst IP
    std::cout << "proto   : " <<std::get<2>(key) << ", ";               // proto
    std::cout << "tos     : " <<std::get<3>(key) << ", " << std::endl;               // tos
    std::cout << "src port: " <<std::get<4>(key) << ", ";               // src port
    std::cout << "dst port: " <<std::get<5>(key) << std::endl;               // dst port
    std::cout << "-------------" << std::endl;
  }
  std::cout << "=============" << std::endl;
}

int export_flow(Flowformat flow_to_export) {
  // export flow
  // create a netflow packet to send
  NetFlowPacket *netflowpacket = new NetFlowPacket;
  // create netflow header
  Netflowhdr netflowhdr;
  netflowhdr.version = htons(5);        // yes
  netflowhdr.count = htons(1);          // yes
  netflowhdr.sys_uptime = 0;            // ?
  netflowhdr.unix_sec = 0;              // yes
  netflowhdr.unix_nsecs = 0;            // yes
  netflowhdr.flow_sequence = flow_seq++;// yes - cislo flow, inkrementace pri generovani flows
  netflowhdr.engine_type = 0;           // ?
  netflowhdr.engine_id = 0;             // ?
  netflowhdr.sampling_interval = 0;     // ?
  // add the flowrecord data to the packet
  netflowpacket->netflowhdr = netflowhdr;
  // TODO maybe Segfault
  netflowpacket->flowformat = flow_to_export;    // do I have to memcpy or sth like that?
  // send the flow
  int msg_size = 100; // FIXME how many
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
  else
    printf("msg sent successfully\n");

  return 0; // success ir return flow or sth
}

/**
 * @brief FIXME return FlowKey, FlowRecord or int? Fro error reporting etc.
 * 
 * @return int 
 */
int record_flow(Flowformat *flow) {

  u_int32_t current_time = flow->first; // my current time, TODO check if htonl whould be used

  printf_flows();   // TODO remove

  // iterate through all flows and check active and inactive timers
  auto key_value = flows.begin();
  while (key_value != flows.end()) {
    Flowformat& flowsIterator = key_value->second;
    // active and inactive timer check + export
    if (current_time - flowsIterator.first > opts->active_timer /* TODO check seconds and type */
        || current_time - flowsIterator.last > opts->inactive_timer) {
      // export flow
      export_flow(flowsIterator);
      
      // remove flow from flows
      key_value = flows.erase(key_value); // do I have to delete the record somehow with delete?
    } else {
      key_value++;
    }
  }

  // cache size (count) check + export
  printf("m-----------------%d and flows size: %ld\n", opts->count, flows.size());  // TODO remove
  if (flows.size() >= opts->count) {
    u_int32_t min = 765746355;  // FIXME: use now() function for getting the current time - it will be the maximum every time or use the time of the first packet
    FlowKey toRemove;           // packet with the minimal value -> the one to be removed
    // iterate through the flows to get the oldest one
    for (auto& key_value : flows) {
      if (key_value.second.first < min) {
        min = key_value.second.first;
        toRemove = key_value.first;
      }
    }
    // export the flow
    export_flow(flows[toRemove]);

    // erase it
    flows.erase(toRemove);
  }

  // key of the current flow
  FlowKey capturedFlow = std::make_tuple(flow->srcaddr, flow->dstaddr, flow->prot, 
                                          flow->tos, flow->srcport, flow->dstport);

  // find the current flow in the flows
  if (flows.find(capturedFlow) != flows.end()) {
    // if exists then update the record
    printf("Flow is already present in flows.\n");
    // TODO update the record in CapturedFlow index //flows[capturedFlow].last = htonl(header->ts.tv_sec);  // FIXME wrong date
  } else {
    // if doesn't exist then create new record
    printf("Flow wasn't found in flows, inserting...\n");
    // insert the flow
    flows[capturedFlow] = *flow;   // TODO *flow or flow - memleak/segfault
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
  //flowformat->dOctets = 0;     // yes - suma header length - Layer 3 bytes in packets - which bytes are computed?
  flowformat->srcport = udp->source; //htons(std::get<4>(capturedFlow));  // yes
  flowformat->dstport = udp->dest; //htons(std::get<5>(capturedFlow));  // yes
  flowformat->tcp_flags = 0;                               // yes - cumulative OR

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
  //flowformat->dOctets = 0;     // yes - suma header length - Layer 3 bytes in packets - which bytes are computed?
  flowformat->srcport = tcp->th_sport; //htons(std::get<4>(capturedFlow));  // yes
  flowformat->dstport = tcp->th_dport; //htons(std::get<5>(capturedFlow));  // yes
  flowformat->tcp_flags = 0;                               // yes - cumulative OR

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

  // TODO port from code and type
  // print type, code, checksum and frame data
  if (icmp->type == 0)
      printf("type: 0 (Echo reply)\n");
  else if (icmp->type == 8)
      printf("type: 8 (Echo request)\n");
  else
      printf("type: %d\n", icmp->type);
  printf("code: %d\n", icmp->code);

  // update the flowformat record with the info found in ipv4 protocol
  flowformat->input = 0;                                   // no
  flowformat->output = 0;                                  // no
  //flowformat->dOctets = 0;     // yes - suma header length - Layer 3 bytes in packets - which bytes are computed?
  flowformat->srcport = 0; //htons(std::get<4>(capturedFlow));  // yes
  flowformat->dstport = 0; //htons(std::get<5>(capturedFlow));  // yes
  flowformat->tcp_flags = 0;                               // yes - cumulative OR

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
  flowformat->dOctets = 0;     // TODO // yes - suma header length - Layer 3 bytes in packets - which bytes are computed?
  flowformat->prot = ip->ip_p;            // yes
  flowformat->tos = ip->ip_tos;             // yes

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

  // count and print RFC3339 timestamp
  char ts_buf[MAX_TIMESTAMP_LEN];
  struct tm *tm = localtime(&(header->ts.tv_sec));
  if (tm == nullptr) {
    fprintf(stderr, "localtime: %s\n", strerror(errno));
    pcap_breakloop(pcap);
    return;
  }
  // get YYYY-MM-DDTHH:MM:SS from tm
  if (strftime(ts_buf, 100, "%FT%T.", tm) == 0) {
    fprintf(stderr, "main: Invalid timestamp\n");
    pcap_breakloop(pcap);
    return;
  }
  printf("%s", ts_buf);

  // count and print milliseconds (time in milliseconds == seconds * 1000)
  snprintf(ts_buf, MAX_TIMESTAMP_LEN - 1, "%lld", header->ts.tv_sec*1000LL + header->ts.tv_usec/1000);
  size_t len = strlen(ts_buf);
  printf("%c%c%c", ts_buf[len-3], ts_buf[len-2], ts_buf[len-1]);

  // count and print time zone offset
  long tz_off = tm->tm_gmtoff / 3600;
  if (tz_off >= 0)
    printf("+%02lu.00\n", tz_off);
  else
    printf("-%02lu.00\n", (-tz_off));

  Flowformat *flowformat = new Flowformat;
  // add the time and other useful information to the flowrecord
  flowformat->srcaddr = 0;  // yes
  flowformat->dstaddr = 0; // std::get<1>(capturedFlow).s_addr;  // yes
  flowformat->nexthop = 0;                                 // no OK
  flowformat->input = 0;                                   // no
  flowformat->output = 0;                                  // no
  flowformat->dPkts = htonl(1);                            // yes - one packet currently
  flowformat->dOctets = 0;                                 // yes - suma header length - Layer 3 bytes in packets - which bytes are computed?
  flowformat->first = htonl(header->ts.tv_sec);            // yes - SysUptime at start of flow -> time in the first packet of the flow hopefully? FIXME
  flowformat->last = htonl(header->ts.tv_sec);             // yes - same as .first -> if this the only packet I think this is right
  flowformat->srcport = 0; //htons(std::get<4>(capturedFlow));  // yes
  flowformat->dstport = 0; //htons(std::get<5>(capturedFlow));  // yes
  flowformat->pad1 = 0;                                    // no OK
  flowformat->tcp_flags = 0;                               // yes - cumulative OR
  flowformat->prot = 0; //std::get<2>(capturedFlow);            // yes
  flowformat->tos = 0; //std::get<3>(capturedFlow);             // yes
  flowformat->src_as = 0;                                  // no OK
  flowformat->dst_as = 0;                                  // no OK
  flowformat->src_mask = 32;                               // yes - 32?
  flowformat->dst_mask = 32;                               // yes - 32?
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
  printf("\n");

  // adding and wexporting netflows done in process_tcp/udp/icmp functions.
  // TODO to have a clean code and delte objects in the same functions where they were created:
  delete flowformat;

  printf("--------- ONE FRAME PROCESSED -----------\n");
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

  printf("Hnusne zlobive sietocky\n");
  
  // create a socket for exporting the flows to the collector
  struct sockaddr_in server, client;   // address structures of the server and the client
  struct hostent *servent;         // network host entry required by gethostbyname()
  socklen_t len;        

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
  
  printf("* Server socket created\n");
     
  len = sizeof(server);
  //fromlen = sizeof(client);

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
  // iterate through the flows map and export each packet
  auto key_value = flows.begin();
  while (key_value != flows.end()) {
    Flowformat& flowToExport = key_value->second;
    // export flow
    export_flow(flowToExport);

    // TODO remove - just for debugging
    // obtain the local IP address and port using getsockname()
    if (getsockname(sock,(struct sockaddr *) &client, &len) == -1)
      err(1,"getsockname() failed");
    printf("* Data sent from %s, port %d (%d) to %s, port %d (%d)\n",inet_ntoa(client.sin_addr), ntohs(client.sin_port), client.sin_port, inet_ntoa(server.sin_addr),ntohs(server.sin_port), server.sin_port);

    // remove flow from flows
    key_value = flows.erase(key_value); // do I have to delete the record somehow with delete?
  }

  // release the resources, close the pcap and socket and return
  release_resources();
  return 0;
}