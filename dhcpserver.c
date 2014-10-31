#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/errno.h>
#include <time.h>
#include <ctype.h>
#include <regex.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "dhcpserver.h"
#include "args.h"
#include "dhcp.h"
#include "options.h"

/*
 * Global pool
 */

address_pool pool;

/*
 * Create a new binding
 * 
 * The binding is added to the pool binding list,
 * and a pointer to the binding is returned for further manipulations.
 */

address_binding *add_binding (uint32_t address, uint8_t cident_len, uint8_t *cident, int status, int flags)
{
    // fill binding

    address_binding *binding = calloc(1, sizeof(*binding));

    binding->address = address;
    memcpy(binding->cident, cident, cident_len);

    binding->assoc_time = time();
    binding->lease_time = pool.default_lease_time;

    binding->status = status;
    binding->flags = flags;

    // add to binding list

    LIST_INSERT_HEAD(&pool.bindings, binding, pointers);
    
    return binding;
}

/*
 * DHCP server functions
 */

dhcp_message *prepare_dhcp_offer (dhcp_message *msg, size_t len, dhcp_option *opts, address_assoc *assoc)
{
     dhcp_message *reply = calloc(1, sizeof(*msg));

     reply->op = BOOTREPLY;

     reply->htype = ETHERNET;
     reply->hlen  = ETHERNET_LEN;

     reply->xid = msg->xid;
     reply->secs = msg->secs;
     
     // TODO: flags for multicast
     // see RFC

     reply->yiaddr = htonl(assoc->address);
     reply->siaddr = htonl(pool.server_id);

     // TODO: relay ip agent
     // see RFC

     memcpy(&reply->chaddr, &msg->chaddr, sizeof(msg->chaddr));

     /* Begin filling of options */

     dhcp_option *dst = &reply.options;
     uint8_t  *my_end = reply + sizeof(*reply);

     memcpy(dst, option_magic, 4); // set option magic bytes
     dst = ((uint8_t *)dst) + 4;

     dhcp_option type = { DHCP_MESSAGE_TYPE, 1,  };
     
     dhcp_option *requested_opts = search_option(opts, len - DHCP_HEADER_SIZE, PARAMETER_REQUEST_LIST);

     if (requested_opts) {

         uint8_t *id = &requested_opts->data;

         uint8_t *end = msg + len < id + requested_opts->len ? 
                        msg + len :
                        id + requested_opts->len;

         for (; id < end; id++) { // NOTE: we don't check attacks on length...

             if(pool.options[*id].id != 0) {

                 if(dst + pool.options[*id].len + 2 > my_end) { // check bounds for our reply buffer
                     free(reply);
                     return NULL;
                 }

                 dst = copy_option (dst, &pool.options[*id]); // set requested option
             }

         }

         dst = copy_option (dst, &pool.options[END]); // set end option

     }
     
}

dhcp_message *serve_dhcp_discover (dhcp_message *msg, size_t len, dhcp_option *opts)
{  
    address_assoc *assoc = search_static_assoc(msg);

    if (assoc) { // a static association has been configured for this client

        log_info("Offer to '%s' of address '%s', current status '%s', %sexpired",
                 str_mac(msg->chaddr), str_ip(assoc->address),
                 str_status(assoc->status),
                 assoc->expire_time < time() ? "" : "not ");
            
        if (assoc->expire_time < time()) assoc->status = PENDING;
            
        return prepare_dhcp_offer(msg, NULL, assoc);

    }

    else { // use dynamic pool

        /* If an address is available, the new address
           SHOULD be chosen as follows: */

        assoc = search_dynamic_assoc(msg);

        if (assoc) {

            /* The client's current address as recorded in the client's current
               binding, ELSE */

            /* The client's previous address as recorded in the client's (now
               expired or released) binding, if that address is in the server's
               pool of available addresses and not already allocated, ELSE */

            // TODO log
            
            return prepare_dhcp_offer(msg, tables.pool, assoc);

        }


        /* The address requested in the 'Requested IP Address' option, if that
           address is valid and not already allocated, ELSE */

        /* A new address allocated from the server's pool of available
           addresses; the address is selected based on the subnet from which
           the message was received (if 'giaddr' is 0) or on the address of
           the relay agent that forwarded the message ('giaddr' when not 0). */

        assoc = add_dynamic(msg);

        return prepare_dhcp_offer(msg, tables.pool, assoc);

    }   
    
}

dhcp_message *serve_dhcp_request (dhcp_message *msg, size_t len, dhcp_option *opts)
{  
    uint32_t server_id = get_server_id(opts);

    if (server_id == pool.server_id) { // this request is an answer to our offer
	
	dhcp_binding binding = search_pending_binding(msg);

	if (binding) {

	    commit_binding(binding);
	    return prepare_dhcp_ack(msg, opts);
	    
	} else {

	    release_binding(binding);
	    return prepare_dhcp_nak(msg, opts);

	}

    }

    else if (server_id) { // this request is an answer to the offer of another server

	dhcp_binding binding = search_pending_binding(msg);
	release_binding(binding);

	return NULL;

    }

    else {

	// TODO: other cases
	return NULL;

    }

}

dhcp_message *serve_dhcp_decline (dhcp_message *msg, size_t len, dhcp_option *opts)
{
    dhcp_binding binding = search_pending_binding(msg);

    log_error("Declined address by '%s' of address '%s'",
	      str_mac(msg->chaddr), str_ip(assoc->address));

    release_binding(binding);

    return NULL;
}

dhcp_message *serve_dhcp_release (dhcp_message *msg, size_t len, dhcp_option *opts)
{
    dhcp_binding binding = search_pending_binding(msg);

    log_info("Released address by '%s' of address '%s'",
	      str_mac(msg->chaddr), str_ip(assoc->address));

    release_binding(binding);

    return NULL;
}

dhcp_message *serve_dhcp_inform (dhcp_message *msg, size_t len, dhcp_option *opts)
{
    // TODO

    return NULL;
}

/*
 * Dispatch client DHCP messages to the correct handling routines
 */

void message_dispatcher (sockaddr_in server_sock, int s)
{
     
    while (1) {
	struct sockaddr_in client_sock;
	socklen_t slen = sizeof(client_sock);
	size_t len;

	dhcp_message message;
	dhcp_option *opt;

	uint8_t *opts;
	uint8_t type;

	if ((len = dhcp_recv_message(s, &message, &client_sock, &slen)) < 0) {
	    continue;
	}

	if (len < 300) { // TODO
	    printf("%s.%u: request with invalid size received\n",
		   inet_ntoa(client_sock.sin_addr), ntohs(client_sock.sin_port));
	    continue;
	}

	if (message.op != BOOTREQUEST)
	    continue;

	if (memcmp(message.options, option_magic, sizeof(option_magic)) != 0) { // TODO
	    printf("%s.%u: request with invalid option magic\n",
		   inet_ntoa(client_sock.sin_addr), ntohs(client_sock.sin_port));
	    continue;
	}

	opts = message.options + sizeof(option_magic);
	opt = search_option(DHCP_MESSAGE_TYPE,
			    len - DHCP_HEADER_SIZE - sizeof(option_magic), opts);

	if (opt == NULL) {
	    printf("%s.%u: request without DHCP message type option\n",
		   inet_ntoa(client_sock.sin_addr), ntohs(client_sock.sin_port));
	    continue;
	}

	switch (opt->data[0]) {

	case DHCPDISCOVER:
            serve_dhcp_discover(message, len, opts);

	case DHCPREQUEST:
	    serve_dhcp_request(message, len, opts);

	case DHCPDECLINE:
	    serve_dhcp_decline(message, len, opts);

	case DHCPRELEASE:
	    serve_dhcp_release(message, len, opts);

	case DHCPINFORM:
	    serve_dhcp_inform(message, len, opts);

	default:
	    printf("%s.%u: request with invalid DHCP message type option\n",
		   inet_ntoa(client_sock.sin_addr), ntohs(client_sock.sin_port));
	    break;
	
	}

    }

}

int main (int argc, char *argv[])
{
    int s;
    uint16_t port;
    struct protoent *pp;
    struct servent *ss;
    struct sockaddr_in server_sock;

    /* Initialize global pool */

    memset(&pool, 0, sizeof(pool));
    LIST_INIT(&pool.bindings);

    /* Load configuration */

    load_global_config();
    load_static_bindings();

    /* Set up server */

    if ((ss = getservbyname("bootps", "udp")) == 0) {
        fprintf(stderr, "server: getservbyname() error\n");
        exit(1);
    }

     if ((pp = getprotobyname("udp")) == 0) {
          fprintf(stderr, "server: getprotobyname() error\n");
          exit(1);
     }

     if ((s = socket(AF_INET, SOCK_DGRAM, pp->p_proto)) == -1) {
          perror("server: socket() error");
          exit(1);
     }

     server_sock.sin_family = AF_INET;
     server_sock.sin_addr.s_addr = htonl(INADDR_ANY);
     server_sock.sin_port = ss->s_port;

     if (bind(s, (struct sockaddr *) &server_sock, sizeof(server_sock)) == -1) {
         perror("server: bind()");
         close(s);
         exit(1);
     }

     printf("dhcp server: listening on %d\n", ntohs(server_sock.sin_port));

     /* Message processing loop */
     
     message_dispatcher(server_sock, s);

     close(s);

     return 0;
}
