#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/queue.h>
#include <arpa/inet.h>

#include "bindings.h"

/*
 * Initialize the binding list.
 */

void
init_binding_list (binding_list *list)
{
    //*list = LIST_HEAD_INITIALIZER(*list);
    LIST_INIT(list);
}

/*
 * Create a new binding
 * 
 * The binding is added to the binding list,
 * and a pointer to the binding is returned for further manipulations.
 */

address_binding *
add_binding (binding_list *list, uint32_t address,
	     uint8_t *cident, uint8_t cident_len, int is_static)
{
    // fill binding

    address_binding *binding = calloc(1, sizeof(*binding));

    binding->address = address;
    binding->cident_len = cident_len;
    memcpy(binding->cident, cident, cident_len);

    binding->is_static = is_static;

    // add to binding list

    LIST_INSERT_HEAD(list, binding, pointers);
    
    return binding;
}

/*
 * Updated bindings status, i.e. set to EXPIRED the status of the 
 * expired bindings.
 */

void
update_bindings_statuses (binding_list *list)
{
    address_binding *binding, *binding_temp;
    
    LIST_FOREACH_SAFE(binding, list, pointers, binding_temp) {
	if(binding->binding_time + binding->lease_time < time(NULL)) {
	    binding->status = EXPIRED;
	}
    }
}

/*
 * Search a static or dynamic binding having the given client identifier.
 *
 * If the is_static option is true a static binding will be searched,
 * otherwise a dynamic one. If status is not zero, an binding with that
 * status will be searched.
 */

address_binding *
search_binding (binding_list *list, uint8_t *cident, uint8_t cident_len,
		int is_static, int status)
{
    address_binding *binding, *binding_temp;
	
    LIST_FOREACH_SAFE(binding, list, pointers, binding_temp) {

	if((binding->is_static == is_static || is_static == STATIC_OR_DYNAMIC) &&
	   binding->cident_len == cident_len &&
	   memcmp(binding->cident, cident, cident_len) == 0) {

	    if(status == 0)
		return binding;
	    else if(status == binding->status)
		return binding;
	}
    }

    return NULL;
}

/*
 * Get an available free address
 *
 * If a zero address is returned, no more address are available.
 */

static uint32_t
take_free_address (pool_indexes *indexes)
{
    if(indexes->current <= indexes->last) {

	uint32_t address = indexes->current;	
	indexes->current = htonl(ntohl(indexes->current) + 1);
	return address;

    } else
	return 0;
}

/*
 * Create a new dynamic binding or reuse an expired one.
 *
 * An attemp will be made to assign to the client the requested IP address
 * contained in the address option. An address equals to zero means that no 
 * specific address has been requested.
 *
 * If the dynamic pool of addresses is full a NULL pointer will be returned.
 */

address_binding *
new_dynamic_binding (binding_list *list, pool_indexes *indexes, uint32_t address,
		     uint8_t *cident, uint8_t cident_len)
{
    address_binding *binding, *binding_temp;
    address_binding *found_binding = NULL;
    int found = 0;

    if (address != 0) {

	LIST_FOREACH_SAFE(binding, list, pointers, binding_temp) {
	    // search a previous binding using the requested IP address

	    if(binding->address == address) {
		found_binding = binding;
		break;
	    }
	}
    }

    if(found_binding != NULL &&
       !found_binding->is_static &&
       found_binding->status != PENDING &&
       found_binding->status != ASSOCIATED) {

	// the requested IP address is available (reuse an expired association)
	return found_binding;
	
    } else {

	/* the requested IP address is already in use, or no address has been
           requested, or the address requested has never been allocated
           (we do not support this last case and just return the next
           available address!). */

	uint32_t address = take_free_address(indexes);

	if(address != 0)
	    return add_binding(list, address, cident, cident_len, 0);

	else { // search any previously assigned address which is expired
    
	    LIST_FOREACH_SAFE(binding, list, pointers, binding_temp) {
		if(!binding->is_static &&
		   found_binding->status != PENDING &&
		   found_binding->status != ASSOCIATED)
		    return binding;
	    }

	    // if executions reach here no more addresses are available
	    return NULL;
	}	
    }

    // execution should not reach here...
    return NULL;
}
