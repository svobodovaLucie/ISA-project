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




/**
 * Function prints the formatted frame data to the standard output.
 * Format of one line:
 * 0x0000  xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  ........ ........
 * xx - hexadecimals, . - characters (non-printable character is printed as '.')
 *
 * @param length frame length
 * @param frame frame data
 */
void print_frame(size_t length, const u_char *frame) {
    size_t n = 0;       //  printed lines counter
    size_t i = 0;       // position to be printed in the frame data string
    size_t full_rows = length - (length % FRAME_PRINT_LEN); // number of rows with 16 characters
    size_t j;           // loop counter

    // print all rows with length == 16 characters (FRAME_PRINT_LEN)
    while (n < full_rows) {
        // print one row
        // print hexadecimals
        printf("0x%04lx:  ", n);
        for (unsigned k = 0; k < 2; k++) {
            for (j = 0; j < FRAME_PRINT_LEN/2; j++) {
                printf("%02x ", frame[i++]);
            }
            printf(" ");
        }
        // print characters
        i = i - FRAME_PRINT_LEN;
        for (unsigned k = 0; k < 2; k++) {
            for (j = 0; j < FRAME_PRINT_LEN/2; j++) {
                if (isprint(frame[i])) {
                    printf("%c", frame[i]);
                } else {
                    printf(".");
                }
                i++;
            }
            printf(" ");
        }
        n = n + FRAME_PRINT_LEN;
        printf("\n");
    }
    // print last row
    printf("0x%04lx:  ", n);
    while (i < length) {
        printf("%02x ", frame[i++]);
    }
    for (size_t num_of_spaces = 0; num_of_spaces < FRAME_PRINT_LEN - (length % FRAME_PRINT_LEN); num_of_spaces++) {
        printf("   ");
    }
    printf("  ");
    i = n;
    j = 0;
    while (i < length) {
        if (j++ == 8)
            printf(" ");
        if (isprint(frame[i])) {
            printf("%c", frame[i]);
        } else {
            printf(".");
        }
        i++;
    }
    printf("\n");
}

/**
 * Function prints more information about UDP packet. It prints source
 * and destination ports, checksum and the frame data;
 *
 * @param header packet header
 * @param packet frame data
 * @param header_length length of the IP header
 */
void process_udp(struct pcap_pkthdr header, const u_char *packet, unsigned int header_length) {
    printf("protocol: UDP\n");
    // cast frame data to udphdr structure
    struct udphdr *udp = (struct udphdr *)(packet + header_length);

    // print source and destination ports
    printf("src port: %u\n", ntohs(udp->source));
    printf("dst port: %u\n", ntohs(udp->dest));
    // print checksum
    printf("checksum: 0x%04x\n", ntohs(udp->check));
    // print frame data
    print_frame(header.caplen, packet);
}

/**
 * Function prints more information about TCP packet. It prints source
 * and destination ports, checksum and frame data.
 *
 * @param header packet header
 * @param packet frame data
 * @param header_length length of the IP header
 */
void process_tcp(struct pcap_pkthdr header, const u_char *packet, unsigned int header_length) {
    printf("protocol: TCP\n");
    // cast frame data to tcphdr structure
    struct tcphdr *tcp = (struct tcphdr *)(packet + header_length);

    // print source and destination ports
    printf("src port: %u\n", ntohs(tcp->source));
    printf("dst port: %u\n", ntohs(tcp->dest));
    // print checksum
    printf("checksum: 0x%04x\n", ntohs(tcp->check));
    // print frame data
    print_frame(header.caplen, packet);
}

/**
 * Function prints more information about ICMP packet - type, code, checksum
 * and the frame data.
 *
 * @param header packet header
 * @param packet frame data
 * @param header_length length of the IP header
 */
void process_icmp(struct pcap_pkthdr header, const u_char *packet, unsigned int header_length) {
    // cast to icmphdr structure
    struct icmphdr *icmp = (struct icmphdr *)(packet + header_length);

    // print type, code, checksum and frame data
    if (icmp->type == 0)
        printf("type: 0 (Echo reply)\n");
    else if (icmp->type == 8)
        printf("type: 8 (Echo request)\n");
    else
        printf("type: %d\n", icmp->type);
    printf("code: %d\n", icmp->code);
    printf("checksum: 0x%04x\n", ntohs(icmp->checksum));
    print_frame(header.caplen, packet);
}

/**
 * Function processes IPv4 packet. It checks the header length and IP version,
 * prints IP addresses and call appropriate function to print more information.
 *
 * @param header packet header
 * @param packet packet data
 */
void process_ipv4(struct pcap_pkthdr header, const u_char *packet) {
    struct ip *ip = (struct ip*)(packet + ETH_HEADER_SIZE);       // IP header
    // check the IP header length and IP version number
    if (ip->ip_hl * 4 < 20 || ip->ip_v != 4) {
        printf("packet with invalid header catched\n");
        pcap_breakloop(pcap);
        return;
    }
    // print source and destination IP addresses
    printf("src IP: %s\n", inet_ntoa(ip->ip_src));
    printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));

    // check protocol type (TCP/UDP/ICMP) and print more information
    if (ip->ip_p == TCP)
        process_tcp(header, packet, ETH_HEADER_SIZE + (ip->ip_hl * 4));
    else if (ip->ip_p == UDP)
        process_udp(header, packet, ETH_HEADER_SIZE + (ip->ip_hl * 4));
    else if (ip->ip_p == ICMPv4) {
        printf("protocol: ICMP\n");
        process_icmp(header, packet, ETH_HEADER_SIZE + (ip->ip_hl * 4));
    }
}


/**
 * Function processes IPv6 packet. It prints IP addresses, checks what the
 * next header number is and loops through the extension headers if present.
 * It calls appropriate functions to process the protocols (TCP, UCP, ICMPv6).
 * If an error occurs, it calls pcap_breakloop() function, which breaks
 * pcap_loop(), that is sniffing the packets.
 *
 * @param header packet header
 * @param packet frame data
 */
void process_ipv6(struct pcap_pkthdr header, const u_char *packet) {
    // create a structure from the packet string
    struct ip6_hdr *ip6 = (struct ip6_hdr *)(packet + ETH_HEADER_SIZE);

    // process IP addresses
    char ip6address[INET6_ADDRSTRLEN] = "\0";   // stores the IP addresses in the right format
    const char *ip6address_res;                 // stores the pointer returned from convert function

    // get the src IP address
    if ((ip6address_res = inet_ntop(AF_INET6, &(ip6->ip6_src), ip6address, INET6_ADDRSTRLEN)) == nullptr) {
        fprintf(stderr, "inet_ntop: %s\n", strerror(errno));
        pcap_breakloop(pcap);
        return;
    }
    // print the src IP address
    printf("src IP: %s\n", ip6address_res);

    // get the dst IP address
    if ((ip6address_res = inet_ntop(AF_INET6, &(ip6->ip6_dst), ip6address, INET6_ADDRSTRLEN)) == nullptr) {
        fprintf(stderr, "inet_ntop: %s\n", strerror(errno));
        pcap_breakloop(pcap);
        return;
    }
    // print the dst IP address
    printf("dst IP: %s\n", ip6address_res);

    // get the position where the next header is located
    size_t current_length = ETH_HEADER_SIZE + IPV6_HEADER_SIZE;

    // print next header number
    printf("next header: %d\n", ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);

    // check if the next header is TCP/UDP/ICMPv6 and process it
    if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == TCP) {
        process_tcp(header, packet, current_length);
        return;
    } else if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == UDP) {
        process_udp(header, packet, current_length);
        return;
    } else if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == ICMPv6) {
        printf("protocol: ICMPv6\n");
        process_icmp(header, packet, current_length);
        return;
    }

    // the next header is some extension headers - create a structure for extension header
    struct ip6_ext *ext = (struct ip6_ext *)(packet + current_length);

    // loop to get through all the extension headers and try to find TCP/UDP/ICMPv6
    while (current_length < header.caplen) {
        if (ext->ip6e_nxt == TCP) {
            process_tcp(header, packet, current_length);
            return;
        }else if (ext->ip6e_nxt == UDP) {
            process_udp(header, packet, current_length);
            return;
        } else if (ext->ip6e_nxt == ICMPv6) {
            process_icmp(header, packet, current_length);
            return;
        }

        // add current extension header's length to the current length
        current_length += ext->ip6e_len;

        // there is another extension header
        // load the next extension header to the ext structure
        ext = (struct ip6_ext *)(packet + current_length);

        // print next header number
        printf("next header: %d\n", ext->ip6e_nxt);

        // if the extension header's next header is NO_NEXT_HEADER break the loop
        if (ext->ip6e_nxt == NO_NEXT_HEADER || ext->ip6e_len == 0) {
            break;
        }
    }
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
    if (pcap_compile(pcap, fp, "udp or tcp or icmp or icmp6", 0, PCAP_NETMASK_UNKNOWN) == -1) {
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

    // print src MAC address
    printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    // print dst MAC address
    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    // print frame length
    printf("frame length: %d\n", header->caplen);

    // get etherType
    eth->ether_type = ntohs(eth->ether_type);
    // process and print the packet
    if (eth->ether_type == IPv4)
        process_ipv4(*header, packet);
    else if (eth->ether_type == IPv6)
        process_ipv6(*header, packet);
    printf("\n");


    printf("--------- ONE FRAME PROCESSED -----------\n");
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
 * Function releases all of the allocated resources.
 *
 * @param opts structure that stores command line options
 * @param fp compiled filter
 */
void release_resources(Options *opts, struct bpf_program fp) {
  pcap_close(pcap);           // global pcap handler
  pcap_freecode(&fp);         // compiled filter
  delete opts;             // options structure

  printf("Resources released.\n");
}

int main(int argc, char *argv[]) {
  int res;                    // variable used for storing results from functions
  sigint_received = 0;        // global variable - 0 means SIGINT signal wasn't caught
  int link_layer_header_type; // number of link-layer header type

  // create opts structure for storing command line options
  //options_t *opts = (options_t *)malloc(sizeof(options_t));
  Options *opts = new Options;
  /*
  if (opts == nullptr) {
    fprintf(stderr, "malloc: allocation error\n");
    return 1;
  }
  */
  // load command line options to the opts structure
  if ((res = load_opts(opts, argc, argv)) != 0) {
    // free allocated resources
    /*
    if (opts->interface != nullptr)
      free(opts->interface);
    free(opts);
    */
    // if help was printed - return 0
    if (res == 2) {
      print_help();
      return 0;
    }
    // error occurred - return 1
    return 1;
  }

  printf("command line arguments done\n");

  // create SIGINT handler
  struct sigaction sigint_handler;
  sigint_handler.sa_handler = handle_signal;
  sigemptyset(&sigint_handler.sa_mask);
  sigint_handler.sa_flags = 0;
  sigaction(SIGINT, &sigint_handler, nullptr);

  // main loop
  // TODO ve snifferu jsem mela do {} while - kdybych nemela ETHERNET link layer
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
    pcap_close(pcap);
    delete opts;
    return 1;
  }

  printf("pcap opened eyo\n");

  // create a filter
  struct bpf_program fp;  // structure used for the compiled filter
    if (!make_filter(&fp)) {
        release_resources(opts, fp);
        return 1;
    }

  // process opts->num packets -> print information about every packet
  if (pcap_loop(pcap, -1, process_frame, NULL) != 0) {
      // fewer packets were processed
      fprintf(stderr, "pcap_loop: %s\n", strerror(errno));
  }


  printf("Hnusne zlobive sietocky\n");

  // -------------------------------------------------------------------------------------------
  // create a netflow packet
  /*
  Netflowhdr netflowhdr;
  netflowhdr.version = 5;
  netflowhdr.count = 1;
  netflowhdr.sys_uptime = 0;
  netflowhdr.unix_sec = 0;
  netflowhdr.unix_nsecs = 0;
  netflowhdr.flow_sequence = 0;
  netflowhdr.engine_type = 0;
  netflowhdr.engine_id = 0;
  netflowhdr.sampling_interval = 0;
  
  Flowformat flowformat;
  flowformat.srcaddr = 0;
  flowformat.dstaddr = 0;
  flowformat.nexthop = 0;
  flowformat.input = 0;
  flowformat.output = 0;
  flowformat.dPkts = 0;
  flowformat.dOctets = 0;
  flowformat.first = 0;
  flowformat.last = 0;
  flowformat.srcport = 0;
  flowformat.dstport = 0;
  flowformat.pad1 = 0;
  flowformat.tcp_flags = 0;
  flowformat.prot = 0;
  flowformat.tos = 0;
  flowformat.src_as = 0;
  flowformat.dst_as = 0;
  flowformat.src_mask = 0;
  flowformat.dst_mask = 0;
  flowformat.pad2 = 0;

  NetFlowPacket netflowpacket;
  netflowpacket.netflowhdr = netflowhdr;
  netflowpacket.flowformat = flowformat;
  */

  // -------------------------------------------------------------------------------------------
  // exporting
  int sock;                        // socket descriptor
  int msg_size, i;
  struct sockaddr_in server, client;   // address structures of the server and the client
  struct hostent *servent;         // network host entry required by gethostbyname()
  socklen_t len, fromlen;        
  char buffer[1024];            

  //  Usage: ./flow <address> <port>

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
  fromlen = sizeof(client);

  printf("* Creating a connected UDP socket using connect()\n");                
  // create a connected UDP socket
  if (connect(sock, (struct sockaddr *)&server, sizeof(server))  == -1)
    err(1, "connect() failed");

  //send data to the server
  while((msg_size=read(STDIN_FILENO,buffer,1024)) > 0) 
      // read input data from STDIN (console) until end-of-line (Enter) is pressed
      // when end-of-file (CTRL-D) is received, n == 0
  { 
    i = send(sock,buffer,msg_size,0);     // send data to the server
    if (i == -1)                   // check if data was sent correctly
      err(1,"send() failed");
    else if (i != msg_size)
      err(1,"send(): buffer written partially");

    // obtain the local IP address and port using getsockname()
    if (getsockname(sock,(struct sockaddr *) &client, &len) == -1)
      err(1,"getsockname() failed");

    printf("* Data sent from %s, port %d (%d) to %s, port %d (%d)\n",inet_ntoa(client.sin_addr), ntohs(client.sin_port), client.sin_port, inet_ntoa(server.sin_addr),ntohs(server.sin_port), server.sin_port);
    
    // read the answer from the server 
    if ((i = recv(sock,buffer, 1024,0)) == -1)   
      err(1,"recv() failed");
    else if (i > 0){
      // obtain the remote IP adddress and port from the server (cf. recfrom())
      if (getpeername(sock, (struct sockaddr *)&client, &fromlen) != 0) 
	err(1,"getpeername() failed\n");

      printf("* UDP packet received from %s, port %d\n",inet_ntoa(client.sin_addr),ntohs(client.sin_port));
      printf("%.*s",i,buffer);                   // print the answer
    }
  } 
  // reading data until end-of-file (CTRL-D)

  if (msg_size == -1)
    err(1,"reading failed");
  close(sock);
  printf("* Closing the client socket ...\n");




  release_resources(opts, fp);
  return 0;
}