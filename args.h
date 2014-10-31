#include <stdint.h>
#include <time.h>

#include "dhcpserver.h"

#define NAME "dhcpserver"
#define VERSION "v. 0.1"

char usage_txt[] =
  NAME " - " VERSION 
  "usage: [-a first,last] [-b mac,address] [-l time] [-m time]\n"
  "       [-o opt,value] [-p time] address netmask gateway\n";

/* 
 * Usage description:
 *  -a: specify the pool of free addresses to allocate
 *  -b: specify a static binding
 *  -l: specify the default lease time (in seconds)
 *  -m: specify the maximum lease time (in seconds)
 *  -o: specify a DHCP option for the pool
 *  -p: time in the pending state (in seconds)
 *  address, netmask, gateway: server ip configs
 */

/* Prototypes */

void usage(char *msg, int exit_status);
void parse_args(int argc, char *argv[], address_pool *pool);
