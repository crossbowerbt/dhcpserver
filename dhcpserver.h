#include <stdint.h>
#include <time.h>
#include <sys/queue.h>

#include "options.h"

/*
 *  Single address binding stuff...
 */

// binding status
enum {
    EMPTY = 0,
    ASSOCIATED,
    PENDING,
    EXPIRED,
    RELEASED
};

struct address_binding {
    uint32_t address;     // address
    uint8_t cident_len;   // client identifier len
    uint8_t cident[256];  // client identifier
    
    time_t assoc_time;    // time of association
    time_t lease_time;    // duration of lease

    int status;           // binding status
    int is_static;        // check if it is a static binding

    LIST_ENTRY(address_bindings) pointers; // list pointers, see queue(3)
};

typedef struct address_binding address_binding;

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

    uint32_t first;     // first address of the pool
    uint32_t last;      // last address of the pool
    uint32_t current;   // current unallocated address

    time_t lease_time;      // default duration of a lease
    time_t max_lease_time;  // max acceptable lease time
    time_t pending_time;    // duration of a binding in the pending state

    dhcp_option options[256]; // options for this pool

    LIST_HEAD(address_binding_list, address_binding) bindings; // list of associated addresses, see queue(3)
};

typedef struct address_pool pool;
