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
#include "bindings.h"
#include "args.h"
#include "dhcp.h"
#include "options.h"
#include "logging.h"

/*
 * Global pool
 */

address_pool pool;

/*
 * DHCP server functions
 */

int
init_dhcp_reply (dhcp_message *msg, size_t len, dhcp_message *reply)
{
    reply->op = BOOTREPLY;

    reply->htype = ETHERNET;
    reply->hlen  = ETHERNET_LEN;

    reply->xid = msg->xid;
    reply->secs = msg->secs;
     
    // TODO: flags for multicast
    // see RFC

    // TODO: relay ip agent
    // see RFC

    memcpy(&reply->chaddr, &msg->chaddr, sizeof(msg->chaddr));

    return 1;
}

int
finalize_dhcp_reply (dhcp_message *reply, STAILQ_HEAD *options)
{
    return serialize_option_list(options, reply->options, sizeof(reply->options));
}

int
fill_requested_dhcp_options (dhcp_option *requested_opts, dhcp_option *opts_end, dhcp_option *dst, dhcp_option *dst_end)
{
    uint8_t *id = &requested_opts->data;

    uint8_t *end = opts_end < id + requested_opts->len ? 
	opts_end :
	id + requested_opts->len;
	
    for (; id < end; id++) {
	    
	if(pool.options[*id].id != 0) {
		
	    if(dst + pool.options[*id].len + 2 > dst_end) // check bounds for our reply buffer
		return 0;
		
	    dst = copy_option (dst, &pool.options[*id]); // set requested option
	}
	    
    }

    return 1;
}

dhcp_msg_type
prepare_dhcp_offer_or_ack (dhcp_message *msg, size_t len, dhcp_message *reply, address_assoc *assoc, dhcp_message_type type)
{
    // assign IP address

    reply->yiaddr = htonl(assoc->address);
    reply->siaddr = htonl(pool.server_id);

    /* Begin filling of options */

    dhcp_option *opts = msg->options;
    dhcp_option *opts_end = ((uint8_t *)msg) + len;
    
    dhcp_option *dst = &reply.options;
    uint8_t  *dst_end = reply + sizeof(*reply);

    memcpy(dst, option_magic, 4); // set option magic bytes
    dst = ((uint8_t *)dst) + 4;

    dhcp_option type = { DHCP_MESSAGE_TYPE, 1, type };
    
    dhcp_option *requested_opts = search_option(opts, len - DHCP_HEADER_SIZE, PARAMETER_REQUEST_LIST);

    if (requested_opts) {

	dst = fill_requested_dhcp_options (requested_opts, opts_end, dst, dst_end);

	if(dst == NULL) // no more space on reply message...
	    return NOP;
	
    }

    if(((uint8_t *)dst) + 1 > dst_end)
	return NOP;

    // write end option
    memcpy(dst, END, 1);
    
    return DHCP_OFFER;
}

dhcp_msg_type
serve_dhcp_discover (dhcp_message *msg, size_t len, dhcp_message *reply)
{  
    address_assoc *assoc = search_assoc(pool.bindings, msg->chaddr, 6, STATIC, EMPTY);

    if (assoc) { // a static association has been configured for this client

        log_info("Offer to '%s' of static address '%s', current status '%s', %sexpired",
                 str_mac(msg->chaddr), str_ip(assoc->address),
                 str_status(assoc->status),
                 assoc->assoc_time + assoc->lease_time < time() ? "" : "not ");
            
        if (assoc->assoc_time + assoc->lease_time < time()) {
	    assoc->status = PENDING;
	    assoc->assoc_time = time();
	    assoc->lease_time = pool.pending_time;
	}
            
        return prepare_dhcp_offer(msg, len, reply, assoc);

    }

    else { // use dynamic pool

        /* If an address is available, the new address
           SHOULD be chosen as follows: */

	assoc = search_assoc(pool.bindings, msg->chaddr, 6, DYNAMIC, EMPTY);

        if (assoc) {

            /* The client's current address as recorded in the client's current
               binding, ELSE */

            /* The client's previous address as recorded in the client's (now
               expired or released) binding, if that address is in the server's
               pool of available addresses and not already allocated, ELSE */

	    log_info("Offer to '%s' of dynamic address '%s', current status '%s', %sexpired",
		     str_mac(msg->chaddr), str_ip(assoc->address),
		     str_status(assoc->status),
		     assoc->assoc_time + assoc->lease_time < time() ? "" : "not ");

	    if (assoc->assoc_time + assoc->lease_time < time()) {
		assoc->status = PENDING;
		assoc->assoc_time = time();
		assoc->lease_time = pool.pending_time;
	    }
	    
            return prepare_dhcp_offer(msg, len, reply, assoc);

        } else {

	    /* The address requested in the 'Requested IP Address' option, if that
	       address is valid and not already allocated, ELSE */

	    /* A new address allocated from the server's pool of available
	       addresses; the address is selected based on the subnet from which
	       the message was received (if 'giaddr' is 0) or on the address of
	       the relay agent that forwarded the message ('giaddr' when not 0). */

	    // TODO: extract requested IP address
	    address = search_option...

	    assoc = new_dynamic_assoc (pool.bindings, pool.indexes, address, msg->chaddr, 6);

	    if (assoc == NULL) {
		log_info("Can not offer an address to '%s', no address available.",
			 str_mac(msg->chaddr));
		
		return NOP;
	    }

	    return prepare_dhcp_offer(msg, len, reply, assoc);
	}

    }
    
}

dhcp_msg_type
serve_dhcp_request (dhcp_message *msg, size_t len, dhcp_option *opts)
{
    // TODO: get SERVER_IDENTIFIER from options or error...

    address_assoc *assoc = search_assoc(pool.bindings, msg->chaddr, 6, DONT_CARE, PENDING);
    
    if (server_id == pool.server_id) { // this request is an answer to our offer

	if (assoc != NULL) {

	    assoc->status = ASSOCIATED;
	    return prepare_dhcp_ack(msg, opts);
	    
	} else {

	    return prepare_dhcp_nak(msg, opts);

	}

    }

    else if (server_id) { // this request is an answer to the offer of another server

	assoc->status = EMPTY;
	return NOP;

    }

    else {

	// TODO: other cases
	return NOP;

    }

}

dhcp_msg_type
serve_dhcp_decline (dhcp_message *msg, size_t len, dhcp_option *opts)
{
    address_assoc *assoc = search_assoc(pool.bindings, msg->chaddr, 6, 0, PENDING);
    
    log_info("Released address by '%s' of address '%s', %sin database.",
	     str_mac(msg->chaddr), str_ip(assoc->address),
	     assoc == NULL ? "not " , "");

    assoc->status = EMPTY;

    return NOP;
}

dhcp_msg_type
serve_dhcp_release (dhcp_message *msg, size_t len, dhcp_option *opts)
{
    address_assoc *assoc = search_assoc(pool.bindings, msg->chaddr, 6, 0, ASSOCIATED);
    
    log_info("Released address by '%s' of address '%s', %sassociated.",
	     str_mac(msg->chaddr), str_ip(assoc->address),
	     assoc == NULL ? "not " , "");

    assoc->status = RELEASED;

    return NOP;
}

dhcp_msg_type
serve_dhcp_inform (dhcp_message *msg, size_t len, dhcp_option *opts)
{
    // TODO

    return NOP;
}

/*
 * Dispatch client DHCP messages to the correct handling routines
 */

void
message_dispatcher (int s, struct sockaddr_in server_sock)
{
     
    while (1) {
	struct sockaddr_in client_sock;
	socklen_t slen = sizeof(client_sock);
	size_t len;

	dhcp_message msg;
	dhcp_message reply;

	STAILQ_HEAD(dhcp_option_entry_list, dhcp_option_entry) msg_opts;   // see queue(3)
	STAILQ_HEAD(dhcp_option_entry_list, dhcp_option_entry) reply_opts; // see queue(3)

	STAILQ_INIT(&msg_opts);   // see queue(3)
	STAILQ_INIT(&reply_opts); // see queue(3)

	dhcp_msg_type ret;

	uint8_t *opts;
	uint8_t type;

	if ((len = dhcp_recv_message(s, &msg, &client_sock, &slen)) < 0) {
	    continue;
	}

	if (len < 300) { // TODO
	    log_error("%s.%u: request with invalid size received\n",
		      inet_ntoa(client_sock.sin_addr), ntohs(client_sock.sin_port));
	    continue;
	}

	if (msg.op != BOOTREQUEST)
	    continue;

	if(parse_options_to_list(&msg, len, &msg_opts) == 0) { // TODO: write this function
	    log_error("%s.%u: request with invalid options\n",
		      inet_ntoa(client_sock.sin_addr), ntohs(client_sock.sin_port));
	    continue;
	}

	if (memcmp(msg.options, option_magic, sizeof(option_magic)) != 0) { // TODO
	    log_error("%s.%u: request with invalid option magic\n",
		      inet_ntoa(client_sock.sin_addr), ntohs(client_sock.sin_port));
	    continue;
	}

	opts = msg.options + sizeof(option_magic);
	opt = search_option(DHCP_MESSAGE_TYPE,
			    len - DHCP_HEADER_SIZE - sizeof(option_magic), opts);

	if (opt == NULL) {
	    printf("%s.%u: request without DHCP message type option\n",
		   inet_ntoa(client_sock.sin_addr), ntohs(client_sock.sin_port));
	    continue;
	}

	init_dhcp_reply(&msg, len, &reply);

	switch (opt->data[0]) {

	case DHCPDISCOVER:
            ret = serve_dhcp_discover(&msg, len, &reply);

	case DHCPREQUEST:
	    ret = serve_dhcp_request(&msg, len, &reply);

	case DHCPDECLINE:
	    ret = serve_dhcp_decline(&msg, len, &reply);

	case DHCPRELEASE:
	    ret = serve_dhcp_release(&msg, len, &reply);

	case DHCPINFORM:
	    ret = serve_dhcp_inform(&msg, len, &reply);

	default:
	    printf("%s.%u: request with invalid DHCP message type option\n",
		   inet_ntoa(client_sock.sin_addr), ntohs(client_sock.sin_port));
	    break;
	
	}

	if(ret != NOP)
	    send_dhcp_reply(s, server_sock, client_sock, &reply);

    }

}

int
main (int argc, char *argv[])
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
     
     message_dispatcher(s, server_sock);

     close(s);

     return 0;
}
