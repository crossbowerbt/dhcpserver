#include <stdint.h>
#include <time.h>
#include <sys/queue.h>

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

    pool_indexes indexes;  // used to delimitate a pool of available addresses

    time_t lease_time;      // default duration of a lease
    time_t max_lease_time;  // max acceptable lease time
    time_t pending_time;    // duration of a binding in the pending state

    dhcp_option options[256]; // options for this pool

    LIST_HEAD(address_binding_list, address_binding) bindings; // list of associated addresses, see queue(3)
};

typedef struct address_pool pool;
