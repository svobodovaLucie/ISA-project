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
#include <csignal>
#include <string.h>

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
int load_opts(options_t *opts, int argc, char *argv[])
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

  // initialise the structure with default values
  opts->file.resize(strlen("-") + 2);
  opts->file = "-";
  printf("Capacity2: %ld\n", opts->file.capacity());
                         // "-" -> STDIN
  //opts->netflow_collector = "127.0.0.1";    // TODO IPv4 address
  opts->netflow_collector.resize(strlen("127.0.0.1") + 2);
  opts->netflow_collector = "127.0.0.1";
  printf("Capacity2: %ld\n", opts->netflow_collector.capacity());
  //opts->netflow_collector.copy("127.0.0.1", 9, 0);
  //sprintf(opts->netflow_collector, "127.0.0.1"); // write to netflow_collector
  opts->port = 2055;
  opts->active_timer = 60;
  opts->inactive_timer = 10;
  opts->count = 1024;
  
  // define variables used in getopt_long() function
  opterr = 0; // suppress default error messages
  // parse the command line options using getopt() function
  int res;
  while ((res = getopt(argc, argv, ":f:c:a:i:m:h")) != -1)
  { // TODO port nse nezapisuje jako p, ale je soucasti c za :xxxx
    // while ((res = getopt_long(argc, argv, optstring, longopts, &longindex)) != -1) {
    //  TODO check aby neproslo napr. -m 76565y (ted projde)
    switch (res) {
    case 'h': // help
      // help will be printed in main() - returns 2
      return 2;
    case 'f': // file
      // pokud neni -> stdin (uz nastaveno defaultne, ted jen zajistit aby to byl stdin)
      // zkontrolovat, jestli dana file existuje
      // alokovat misto pro opts->file
      // zkontrolovat malloc
      // zapsat file (musim zapisovat, pokud si ji otevru stejne jako stdin? asi jo, abych ji pak mohla zavrit)

      /*
        // convert string to number if valid
        try {
          //if (std::stoi(optarg) >= 0)
          //  opts->count = std::stoi(optarg);
          //else
          //  throw std::invalid_argument("");
          //printf("bylo zadano f: %s", opts->file);
        } catch (...) {
          fprintf(stderr, "invalid number in command line options\n");
          free(opts->file);   // TODO ne vzdy
          free(opts->netflow_collector);
          return 1;
        }
      */
      printf("f: %s\n", optarg);
      break;
    case 'c':
      
      tmp.resize(260);
      tmp = optarg;
      //sprintf(opts->netflow_collector, "%s", optarg);
      //printf("-c: %s\n", opts->netflow_collector);
      std::cout << "-c: " << opts->netflow_collector << '\n';
      // check address/hostname format
      opts->netflow_collector = tmp.substr(0, tmp.find_last_of(":"));   // address[hostname]
      tmp = tmp.substr(tmp.find_last_of(":") + 1);
      try {
        if (std::stoi(tmp) >= 0)
          opts->port = std::stoi(tmp);
        else
          throw std::invalid_argument("");
      } catch (...) {
        fprintf(stderr, "invalid port number\n");
        //free(opts->file); // TODO ne vzdy
        //free(opts->netflow_collector);
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
        //free(opts->file); // TODO ne vzdy
        //free(opts->netflow_collector);
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
        //free(opts->file); // TODO ne vzdy
        //free(opts->netflow_collector);
        return 1;
      }
      printf("-i: %u\n", opts->inactive_timer);
      break;
    case 'm': //
      try
      {
        if (std::stoi(optarg) >= 0)
          opts->count = std::stoi(optarg);
        else
          throw std::invalid_argument("");
      }
      catch (...)
      {
        fprintf(stderr, "invalid number in command line options\n");
        //free(opts->file); // TODO ne vzdy
        //free(opts->netflow_collector);
        return 1;
      }
      printf("-m: %u\n", opts->count);
      break;
    default: // unknown command line option
      printf("error in command line options (see -h or --help for help)\n");
      //free(opts->file); // TODO ne vzdy
      //free(opts->netflow_collector);
      return 1;
    }
  }
  return 0; // successful
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
 * @param fp compiled filter
 * @param opts structure that stores command line options
 */
void release_resources(options_t *opts) {
  //pcap_close(pcap);           // global pcap handler
  printf("Resoources released.\n");
  //pcap_freecode(&fp);         // compiled filter
  //free(opts->interface);  // options structure - interface string
  //delete opts.file;
  //delete opts->netflow_collector;
  free(opts);             // options structure
}

int main(int argc, char *argv[]) {
  int res;                    // variable used for storing results from functions
  sigint_received = 0;        // global variable - 0 means SIGINT signal wasn't caught
  //int link_layer_header_type; // number of link-layer header type

  // create opts structure for storing command line options
  options_t *opts = (options_t *)malloc(sizeof(options_t));
  if (opts == nullptr) {
    fprintf(stderr, "malloc: allocation error\n");
    return 1;
  }
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

  printf("main looooop...\n");

  /*
  pcap_t *pcap;
  pcap = pcap_open_offline(opts->file.c_str(), errbuf);
  if (pcap == nullptr) {
    fprintf(stderr, "pcap_create: %s", errbuf);
    //free(opts->interface);
    free(opts);
    return 1;
  }
  else {
    printf("pcap opened offline\n");
  }
  */

  printf("Hnusne zlobive sietocky\n");

  release_resources(opts);
  return 0;
}