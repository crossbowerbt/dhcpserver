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
init_binding_list (LIST_HEAD *head)
{
    LIST_INIT(LIST_HEAD *head);
}

/*
 * Create a new binding
 * 
 * The binding is added to the binding list,
 * and a pointer to the binding is returned for further manipulations.
 */

address_binding *
add_binding (LIST_HEAD *head, uint32_t address, uint8_t *cident, uint8_t cident_len)
{
    // fill binding

    address_binding *binding = calloc(1, sizeof(*binding));

    binding->address = address;
    binding->cident_len = cident_len;
    memcpy(binding->cident, cident, cident_len);

    // add to binding list

    LIST_INSERT_HEAD(head, binding, pointers);
    
    return binding;
}

/*
 * Remove a binding.
 * 
 * The binding is also deallocated from memory.
 */

void
remove_binding (address_binding *binding)
{
    LIST_REMOVE(binding, pointers);
}

/*
 * Updated bindings status, i.e. set to EXPIRED the status of the 
 * expired bindings.
 */

void
update_bindings_statuses (LIST_HEAD *head)
{
    LIST_FOREACH_SAFE(assoc, head, pointers, assoc_temp) {
	if(assoc->assoc_time + assoc->lease_time < time()) { // update status of expired entries
	    assoc->status = EXPIRED;
	}
    }
}

/*
 * Search a static or dynamic association having the given client identifier.
 *
 * If the is_static option is true a static association will be searched,
 * otherwise a dynamic one. If status is not zero, an association with that
 * status will be searched.
 */

address_assoc *
search_assoc (LIST_HEAD *head, uint8_t *cident, uint8_t cident_len, int is_static, int status)
{
    LIST_FOREACH_SAFE(assoc, head, pointers, assoc_temp) {

	if((assoc->is_static == is_static || is_static == DONT_CARE) &&
	   assoc->cident_len == cident_len &&
	   memcmp(assoc->cident, cident, cident_len) == 0) {

	    if(status == 0)
		return assoc;
	    else if(status == assoc->status)
		return assoc;
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

	uint32_t address = pool->current;	
	pool->current = htonl(ntohl(pool->current) + 1);
	return address;

    } else
	return 0;
}

/*
 * Create a new dynamic association or reuse an expired one.
 *
 * An attemp will be made to assign to the client the requested IP address
 * contained in the address option. An address equals to zero means that no 
 * specific address has been requested.
 *
 * If the dynamic pool of addresses is full a NULL pointer will be returned.
 */

address_assoc *
new_dynamic_assoc (LIST_HEAD *head, pool_indexes *indexes, uint32_t address, uint8_t *cident, uint8_t cident_len)
{
    address_assoc *found_assoc = NULL;
    int found = 0;

    if (address != 0) {

	LIST_FOREACH_SAFE(assoc, head, pointers, assoc_temp) { // search a previous association using the requested IP address

	    if(memcmp(assoc->address, address, 4) == 0) {
		found_assoc = assoc;
		break;
	    }
	}
    }

    if(found_assoc != NULL &&
       !found_assoc->is_static &&
       found_assoc->status != PENDING &&
       found_assoc->status != ASSOCIATED) { // the requested IP address is available (reuse an expired association)

	return found_assoc;
	
    } else {

	/* the requested IP address is already in use, or no address has been requested,
	   or the address requested has never been allocated (we do not support this last case
	   and just return the next available address!). */

	uint32_t address = take_free_address(indexes);

	if(address != 0)
	    return add_binding(head, address, cident, cident_len);

	else { // search any previously assigned address which is expired
    
	    LIST_FOREACH_SAFE(assoc, head, pointers, assoc_temp) {
		if(!assoc->is_static && found_assoc->status != PENDING && found_assoc->status != ASSOCIATED)
		    return assoc;
	    }

	    // if executions reach here no more addresses are available
	    return NULL;
	}	
    }

    // execution should not reach here...
    return NULL;
}
