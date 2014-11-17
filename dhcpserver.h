#ifndef DHCPSERVER_H
#define DHCPSERVER_H

#include <stdint.h>
#include <time.h>
#include <sys/queue.h>

#include "dhcp.h"
#include "options.h"
#include "bindings.h"

/*
 * Global association pool.
 *
 * The (static or dynamic) associations tables of the DHCP server,
 * are maintained in this global structure.
 *
 * Note: all the IP addresses are in host order,
 *       to allow an easy manipulation.
 */

struct address_pool {
    uint32_t server_id; // this server id (IP address)
    uint32_t netmask;   // network mask
    uint32_t gateway;   // network gateway

    char device[16];    // network device to use

    pool_indexes indexes;  // used to delimitate a pool of available addresses

    time_t lease_time;   // default lease time
    time_t pending_time; // duration of a binding in the pending state

    dhcp_option_list options; // options for this pool, see queue
    
    binding_list bindings; // associated addresses, see queue(3)
};

typedef struct address_pool address_pool;

/*
 * Internal representation of a DHCP message,
 * with options parsed into a list...
 */

struct dhcp_msg {
    dhcp_message hdr;
    dhcp_option_list opts;
};

typedef struct dhcp_msg dhcp_msg;

#endif
