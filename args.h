#include <stdint.h>
#include <time.h>

#define NAME "dhcpserver"
#define VERSION "v. 0.1"

char usage_txt[] =
  NAME " - " VERSION 
  "usage: [-a first,last] [-l time] [-m time] [-o opt,value]\n"
  "       [-p time] address netmask gateway\n";

/* 
 * Usage description:
 *  -a: specify the pool of free addresses to allocate
 *  -l: specify the default lease time (in seconds)
 *  -m: specify the maximum lease time (in seconds)
 *  -o: specify a DHCP option for the pool
 *  -p: time in the pending state (in seconds)
 *  address, netmask, gateway: server ip configs
 */

struct address_pool {
    uint32_t server_id; // this server id (IP address)
    uint32_t netmask;   // network mask
    uint32_t gateway;   // network gateway

    uint32_t first;     // first address of the pool
    uint32_t last;      // last address of the pool
    uint32_t current;   // current unallocated address

    time_t lease_time;      // default duration of a lease
    time_t max_lease_time;  // max acceptable lease time
    time_t pending_time;    // duration of a binding in the pending state

    dhcp_option options[256]; // options for this pool

    address_binding *bindings; // list of associated addresses
};

typedef struct address_pool pool;

/* Prototypes */

void usage(char *msg, int exit_status);
void parse_args(int argc, char *argv[], address_pool *pool);
