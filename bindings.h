#ifndef BINDINGS_H
#define BINDINGS_H

#include <stdint.h>
#include <time.h>

#include "queue.h"
#include "options.h"

/*
 * Header to manage the database of address bindings.
 */

// static association or dynamic
enum {
    DYNAMIC = 0,
    STATIC  = 1,
    STATIC_OR_DYNAMIC = 2
};

// binding status
enum {
    EMPTY = 0,
    ASSOCIATED,
    PENDING,
    EXPIRED,
    RELEASED
};

/*
 * IP address used to delimitate an address pool.
 */

struct pool_indexes {
    uint32_t first;    // first address of the pool
    uint32_t last;     // last address of the pool
    uint32_t current;  // current available address
};

typedef struct pool_indexes pool_indexes;

/*
 * The bindings are organized as a double linked list
 * using the standard queue(3) library
 */

struct address_binding {
    uint32_t address;     // address
    uint8_t cident_len;   // client identifier len
    uint8_t cident[256];  // client identifier
    
    time_t binding_time;  // time of binding
    time_t lease_time;    // duration of lease

    int status;           // binding status
    int is_static;        // check if it is a static binding

    LIST_ENTRY(address_binding) pointers; // list pointers, see queue(3)
};

typedef struct address_binding address_binding;

typedef LIST_HEAD(binding_list_, address_binding) BINDING_LIST_HEAD;
typedef struct binding_list_ binding_list;
						 
/*
 * Prototypes
 */

void init_binding_list (binding_list *list);

address_binding *add_binding (binding_list *list, uint32_t address, uint8_t *cident, uint8_t cident_len, int is_static);
void remove_binding (address_binding *binding);

void update_bindings_statuses (binding_list *list);

address_binding *search_binding (binding_list *list, uint8_t *cident, uint8_t cident_len, int is_static, int status);
address_binding *new_dynamic_binding (binding_list *list, pool_indexes *indexes, uint32_t address, uint8_t *cident, uint8_t cident_len);

#endif
