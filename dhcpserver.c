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
 * Expand a dhcp message into the internal representation.
 *
 * Return the message type on success, 0 on failure.
 */

uint8_t
expand_msg (dhcp_msg *request, size_t len)
{
    STAILQ_INIT(&request.opts);
    
    if (request->hdr.hlen < 1 || request->hdr.hlen > 16)
	return 0;

    if(parse_options_to_list(&request->opts, request->hdr.options,
			     len - DHCP_HEADER_SIZE) == 0)
	return 0;
    
    dhcp_option *type_opt = search_option(&request->opts, DHCP_MESSAGE_TYPE);
    
    if (type_opt == NULL)
	return 0;

    uint8_t type = type_opt->data[0];
    
    return type;
}

int
init_reply (dhcp_msg *request, dhcp_msg *reply)
{
    memset(&reply->hdr, 0, sizeof(reply->hdr));

    STAILQ_INIT(&reply->opts);
    
    reply->hdr.op = BOOTREPLY;

    reply->hdr.htype = request->hdr.htype;
    reply->hdr.hlen  = request->hdr.hlen;

    reply->hdr.xid   = request->hdr.xid;
    reply->hdr.flags = request->hdr.flags;
     
    reply->hdr.giaddr = request->hdr.giaddr;
    
    memcpy(reply->hdr.chaddr, request->hdr.chaddr, request->hdr.hlen);

    return 1;
}

void
fill_requested_dhcp_options (dhcp_option *requested_opts, STAILQ_HEAD *reply_opts)
{
    uint8_t len = requested_opts->len;
    uint8_t *id = requested_opts->data;

    int i;
    for (i = 0; i < len; i++) {
	    
	if(id[i] != 0) {
	    dhcp_option *opt = search_option(pool.options, id);
	    if(opt != NULL)
		append_option(reply_opts, opt);
	}
	    
    }
}

dhcp_msg_type
fill_dhcp_reply (dhcp_msg *request, dhcp_msg *reply,
		 address_binding *assoc, uint8_t type)
{
    static dhcp_option type_opt, server_id_opt, lease_time_opt;

    type_opt.id = DHCP_MESSAGE_TYPE;
    type_opt.len = 1;
    type_opt.data[0] = type;
    append_option(&reply->opts, &type_opt);

    server_id_opt.id = SERVER_ID;
    server_id_opt.len = 4;
    memcpy(server_id_opt.data, &pool.server_id, sizeof(pool.server_id));
    append_option(&reply->opts, &server_id_opt);
    
    if(assoc != NULL) {
	reply->hdr.yiaddr = htonl(assoc->address);

	uint32_t lease_time = htonl(assoc->lease_time);
	lease_time_opt.id = IP_ADDRESS_LEASE_TIME;
	lease_time_opt.len = 4;
	memcpy(lease_time_opt.data, &lease_time, sizeof(lease_time));
	append_option(&reply->opts, &lease_time_opt);
    }
    
    if (type != DHCP_NAK) {
	dhcp_option *requested_opts = search_option(msg_opts, PARAMETER_REQUEST_LIST);

	if (requested_opts)
	    fill_requested_dhcp_options (requested_opts, reply_opts);
    }
    
    return type;
}

dhcp_msg_type
serve_dhcp_discover (dhcp_msg *request, dhcp_msg *reply)
{  
    address_assoc *assoc = search_assoc(pool.bindings, request->hdr.chaddr,
					request->hdr.hlen, STATIC, EMPTY);

    if (assoc) { // a static association has been configured for this client

        log_info("Offer %s to %s (static), %s status %sexpired",
                 str_ip(assoc->address), str_mac(request->hdr.chaddr),
                 str_status(assoc->status),
                 assoc->assoc_time + assoc->lease_time < time() ? "" : "not ");
            
        if (assoc->assoc_time + assoc->lease_time < time()) {
	    assoc->status = PENDING;
	    assoc->assoc_time = time();
	    assoc->lease_time = pool.pending_time;
	}
            
        return fill_dhcp_reply(request, reply, assoc, DHCP_OFFER);

    }

    else { // use dynamic pool

        /* If an address is available, the new address
           SHOULD be chosen as follows: */

	assoc = search_assoc(pool.bindings, request->hdr.chaddr,
			     request->hdr.hlen, DYNAMIC, EMPTY);

        if (assoc) {

            /* The client's current address as recorded in the client's current
               binding, ELSE */

            /* The client's previous address as recorded in the client's (now
               expired or released) binding, if that address is in the server's
               pool of available addresses and not already allocated, ELSE */

	    log_info("Offer %s to %s, %s status %sexpired",
		     str_ip(assoc->address), str_mac(request->hdr.chaddr),
		     str_status(assoc->status),
		     assoc->assoc_time + assoc->lease_time < time() ? "" : "not ");

	    if (assoc->assoc_time + assoc->lease_time < time()) {
		assoc->status = PENDING;
		assoc->assoc_time = time();
		assoc->lease_time = pool.pending_time;
	    }
	    
            return fill_dhcp_reply(request, reply, assoc, DHCP_OFFER);

        } else {

	    /* The address requested in the 'Requested IP Address' option, if that
	       address is valid and not already allocated, ELSE */

	    /* A new address allocated from the server's pool of available
	       addresses; the address is selected based on the subnet from which
	       the message was received (if 'giaddr' is 0) or on the address of
	       the relay agent that forwarded the message ('giaddr' when not 0). */

	    // TODO: extract requested IP address
	    uint32_t address = 0;
	    dhcp_option *address_opt =
		search_option(&request->opts, REQUESTED_IP_ADDRESS);

	    if(address_opt != NULL)
		memcpy(&address, address_opt->data, sizeof(address));
	    
	    assoc = new_dynamic_assoc(pool.bindings, pool.indexes, address,
				      request->hdr.chaddr, request->hdr.hlen);

	    if (assoc == NULL) {
		log_info("Can not offer an address to '%s', no address available.",
			 str_mac(request->hdr.chaddr));
		
		return 0;
	    }

	    return fill_dhcp_reply(request, reply, assoc, DHCP_OFFER);
	}

    }

    // should NOT reach here...
}

dhcp_msg_type
serve_dhcp_request (dhcp_msg *request, dhcp_msg *reply)
{
    address_assoc *assoc = search_assoc(pool.bindings, request->hdr.chaddr,
					request->hdr.hlen, STATIC_OR_DYNAMIC, PENDING);

    uint32_t server_id = 0;
    dhcp_option *server_id_opt = search_option(&request->opts, SERVER_IDENTIFIER);

    if(server_id_opt != NULL)
	memcpy(&server_id, server_id_opt->data, sizeof(server_id));
    
    if (server_id == pool.server_id) { // this request is an answer to our offer

	if (assoc != NULL) {

	    log_info("Ack %s to %s, associated",
		     str_ip(assoc->address), str_mac(request->hdr.chaddr));

	    assoc->status = ASSOCIATED;
	    return fill_dhcp_reply(request, reply, assoc, DHCP_ACK);
	
	} else {

	    log_info("Nak to %s, not associated",
		     str_mac(request->hdr.chaddr));
		    
	    return fill_dhcp_reply(request, reply, NULL, DHCP_NAK);
	}

    } else if (server_id != 0) { // answer to the offer of another server

	log_info("Clearing %s of %s, accepted another server offer",
		 str_ip(assoc->address), str_mac(request->hdr.chaddr));
		    
	assoc->status = EMPTY;
	return 0;

    }

    // malformed request...
    return 0;
}

dhcp_msg_type
serve_dhcp_decline (dhcp_msg *request, dhcp_msg *reply)
{
    address_assoc *assoc = search_assoc(pool.bindings, request->hdr.chaddr,
					request->hdr.hlen, STATIC_OR_DYNAMIC, PENDING);

    if(assoc != NULL) {
	log_info("Declined %s by %s",
		 str_ip(assoc->address), str_mac(request->hdr.chaddr));

	assoc->status = EMPTY;
    }

    return 0;
}

dhcp_msg_type
serve_dhcp_release (dhcp_msg *request, dhcp_msg *reply)
{
    address_assoc *assoc = search_assoc(pool.bindings, request->hdr.chaddr,
					request->hdr.hlen, STATIC_OR_DYNAMIC, ASSOCIATED);

    if(assoc != NULL) {
	log_info("Released %s by %s",
		 str_mac(request->hdr.chaddr), str_ip(assoc->address));

	assoc->status = RELEASED;
    }

    return 0;
}

dhcp_msg_type
serve_dhcp_inform (dhcp_msg *request, dhcp_msg *reply)
{
    log_info("Info to %s", str_mac(request->hdr.chaddr));
	
    return fill_dhcp_reply(request, reply, NULL, DHCP_ACK);
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

	dhcp_msg request;
	dhcp_msg reply;

	uint8_t type;

	if((len = dhcp_recv_message(s, &request.hdr, &client_sock, &slen)) < 300) {
	    continue; // TODO: check the magic number 300
	}

	if(request.hdr.op != BOOTREQUEST)
	    continue;
	
	if((type = expand_request(&request, len)) == 0) {
	    log_error("%s.%u: invalid request received\n",
		      inet_ntoa(client_sock.sin_addr), ntohs(client_sock.sin_port));
	    continue;
	}
	
	init_reply(&request, &reply);

	switch (type) {

	case DHCPDISCOVER:
            type = serve_dhcp_discover(&request, &reply);

	case DHCPREQUEST:
	    type = serve_dhcp_request(&request, &reply);

	case DHCPDECLINE:
	    type = serve_dhcp_decline(&request, &reply);

	case DHCPRELEASE:
	    type = serve_dhcp_release(&request, &reply);

	case DHCPINFORM:
	    type = serve_dhcp_inform(&request, &reply);

	default:
	    printf("%s.%u: request with invalid DHCP message type option\n",
		   inet_ntoa(client_sock.sin_addr), ntohs(client_sock.sin_port));
	    break;
	
	}

	if(type != 0)
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
