#include <stdint.h>
#include <time.h>

#include "dhcpserver.h"

#define NAME "dhcpserver"
#define VERSION "v. 0.1"

#define USAGE_TXT							\
    NAME " - " VERSION "\n"						\
    "usage: [-a first,last] [-d device] [-o opt,value]\n"		\
    "       [-p time] [-s mac,ip] server_address\n"

/* 
 * Usage description:
 *  -a: specify the pool of free addresses to allocate
 *  -d: network device name to use
 *  -o: specify a DHCP option for the pool
 *  -p: time in the pending state (in seconds)
 *  -s: specify a static binding
 */

/* Prototypes */

void usage(char *msg, int exit_status);
void parse_args(int argc, char *argv[], address_pool *pool);
