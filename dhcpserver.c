#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/errno.h>
#include <time.h>
#include <ctype.h>
#include <regex.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <net/if.h>

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
 * Helper functions
 */

char *
str_ip (uint32_t ip)
{
    struct in_addr addr;
    memcpy(&addr, &ip, sizeof(ip));
    return inet_ntoa(addr);
}

char *
str_mac (uint8_t *mac)
{
    static char str[128];

    sprintf(str, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
	    mac[0], mac[1], mac[2],
	    mac[3], mac[4], mac[5]);

    return str;
}

char *
str_status (int status)
{
    switch(status) {
    case EMPTY:
	return "empty";
    case PENDING:
	return "pending";
    case ASSOCIATED:
	return "associated";
    case RELEASED:
	return "released";
    case EXPIRED:
	return "expired";
    default:
	return NULL;
    }
}

/*
 * Network related routines
 */

void
add_arp_entry (int s, uint8_t *mac, uint32_t ip)
{
    struct arpreq ar;
    struct sockaddr_in *sock;

    memset(&ar, 0, sizeof(ar));

    /* add a proxy ARP entry for given pair */
    
    sock = (struct sockaddr_in *) &ar.arp_pa;
    sock->sin_family = AF_INET;
    sock->sin_addr.s_addr = ip;

    memcpy(ar.arp_ha.sa_data, mac, 6);
    ar.arp_flags = ATF_COM; //(ATF_PUBL | ATF_COM);

    strncpy(ar.arp_dev, pool.device, sizeof(ar.arp_dev));
    
    if (ioctl(s, SIOCSARP, (char *) &ar) < 0)  {
	perror("error adding entry to arp table");
    };    
}

void
delete_arp_entry (int s, uint8_t *mac, uint32_t ip)
{
    struct arpreq ar;
    struct sockaddr_in *sock;

    memset(&ar, 0, sizeof(ar));
    
    sock = (struct sockaddr_in *) &ar.arp_pa;
    sock->sin_family = AF_INET;
    sock->sin_addr.s_addr = ip;

    strncpy(ar.arp_dev, pool.device, sizeof(ar.arp_dev));

    if(ioctl(s, SIOCGARP, (char *) &ar) < 0)  {
	if (errno != ENXIO) {
	    perror("error getting arp entry");
	    return;
	}
    };
    
    if(ip == 0 || memcmp(mac, ar.arp_ha.sa_data, 6) == 0) { 
	if(ioctl(s, SIOCDARP, (char *) &ar) < 0) {
	    perror("error removing arp table entry");
	}
    }
}

int
send_dhcp_reply	(int s, struct sockaddr_in *client_sock, dhcp_msg *reply)
{
    size_t len, ret;

    len = serialize_option_list(&reply->opts, reply->hdr.options,
				sizeof(reply->hdr) - DHCP_HEADER_SIZE);

    len += DHCP_HEADER_SIZE;
    
    client_sock->sin_addr.s_addr = reply->hdr.yiaddr; // use the address assigned by us

    if(reply->hdr.yiaddr != 0) {
	add_arp_entry(s, reply->hdr.chaddr, reply->hdr.yiaddr);
    }

    if ((ret = sendto(s, reply, len, 0, (struct sockaddr *)client_sock, sizeof(*client_sock))) < 0) {
	perror("sendto failed");
	return -1;
    }

    return ret;
}

/*
 * Message handling routines.
 */

uint8_t
expand_request (dhcp_msg *request, size_t len)
{
    init_option_list(&request->opts);
    
    if (request->hdr.hlen < 1 || request->hdr.hlen > 16)
	return 0;

    if(parse_options_to_list(&request->opts, (dhcp_option *)request->hdr.options,
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

    init_option_list(&reply->opts);
    
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
fill_requested_dhcp_options (dhcp_option *requested_opts, dhcp_option_list *reply_opts)
{
    uint8_t len = requested_opts->len;
    uint8_t *id = requested_opts->data;

    int i;
    for (i = 0; i < len; i++) {
	    
	if(id[i] != 0) {
	    dhcp_option *opt = search_option(&pool.options, id[i]);

	    if(opt != NULL)
		append_option(reply_opts, opt);
	}
	    
    }
}

int
fill_dhcp_reply (dhcp_msg *request, dhcp_msg *reply,
		 address_binding *binding, uint8_t type)
{
    static dhcp_option type_opt, server_id_opt;

    type_opt.id = DHCP_MESSAGE_TYPE;
    type_opt.len = 1;
    type_opt.data[0] = type;
    append_option(&reply->opts, &type_opt);

    server_id_opt.id = SERVER_IDENTIFIER;
    server_id_opt.len = 4;
    memcpy(server_id_opt.data, &pool.server_id, sizeof(pool.server_id));
    append_option(&reply->opts, &server_id_opt);
    
    if(binding != NULL) {
	reply->hdr.yiaddr = binding->address;
    }
    
    if (type != DHCP_NAK) {
	dhcp_option *requested_opts = search_option(&request->opts, PARAMETER_REQUEST_LIST);

	if (requested_opts)
	    fill_requested_dhcp_options(requested_opts, &reply->opts);
    }
    
    return type;
}

int
serve_dhcp_discover (dhcp_msg *request, dhcp_msg *reply)
{  
    address_binding *binding = search_binding(&pool.bindings, request->hdr.chaddr,
					      request->hdr.hlen, STATIC, EMPTY);

    if (binding) { // a static binding has been configured for this client

        log_info("Offer %s to %s (static), %s status %sexpired",
                 str_ip(binding->address), str_mac(request->hdr.chaddr),
                 str_status(binding->status),
                 binding->binding_time + binding->lease_time < time(NULL) ? "" : "not ");
            
        if (binding->binding_time + binding->lease_time < time(NULL)) {
	    binding->status = PENDING;
	    binding->binding_time = time(NULL);
	    binding->lease_time = pool.pending_time;
	}
            
        return fill_dhcp_reply(request, reply, binding, DHCP_OFFER);

    }

    else { // use dynamic pool

        /* If an address is available, the new address
           SHOULD be chosen as follows: */

	binding = search_binding(&pool.bindings, request->hdr.chaddr,
				 request->hdr.hlen, DYNAMIC, EMPTY);

        if (binding) {

            /* The client's current address as recorded in the client's current
               binding, ELSE */

            /* The client's previous address as recorded in the client's (now
               expired or released) binding, if that address is in the server's
               pool of available addresses and not already allocated, ELSE */

	    log_info("Offer %s to %s, %s status %sexpired",
		     str_ip(binding->address), str_mac(request->hdr.chaddr),
		     str_status(binding->status),
		     binding->binding_time + binding->lease_time < time(NULL) ? "" : "not ");

	    if (binding->binding_time + binding->lease_time < time(NULL)) {
		binding->status = PENDING;
		binding->binding_time = time(NULL);
		binding->lease_time = pool.pending_time;
	    }
	    
            return fill_dhcp_reply(request, reply, binding, DHCP_OFFER);

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
	    
	    binding = new_dynamic_binding(&pool.bindings, &pool.indexes, address,
					  request->hdr.chaddr, request->hdr.hlen);

	    if (binding == NULL) {
		log_info("Can not offer an address to %s, no address available.",
			 str_mac(request->hdr.chaddr));
		
		return 0;
	    }

	    log_info("Offer %s to %s, %s status %sexpired",
		     str_ip(binding->address), str_mac(request->hdr.chaddr),
		     str_status(binding->status),
		     binding->binding_time + binding->lease_time < time(NULL) ? "" : "not ");
	    
	    if (binding->binding_time + binding->lease_time < time(NULL)) {
		binding->status = PENDING;
		binding->binding_time = time(NULL);
		binding->lease_time = pool.pending_time;
	    }

	    return fill_dhcp_reply(request, reply, binding, DHCP_OFFER);
	}

    }

    // should NOT reach here...
}

int
serve_dhcp_request (dhcp_msg *request, dhcp_msg *reply)
{
    address_binding *binding = search_binding(&pool.bindings, request->hdr.chaddr,
					      request->hdr.hlen, STATIC_OR_DYNAMIC, PENDING);

    uint32_t server_id = 0;
    dhcp_option *server_id_opt = search_option(&request->opts, SERVER_IDENTIFIER);

    if(server_id_opt != NULL)
	memcpy(&server_id, server_id_opt->data, sizeof(server_id));
    
    if (server_id == pool.server_id) { // this request is an answer to our offer

	if (binding != NULL) {

	    log_info("Ack %s to %s, associated",
		     str_ip(binding->address), str_mac(request->hdr.chaddr));

	    binding->status = ASSOCIATED;
	    binding->lease_time = pool.lease_time;
	    
	    return fill_dhcp_reply(request, reply, binding, DHCP_ACK);
	
	} else {

	    log_info("Nak to %s, not associated",
		     str_mac(request->hdr.chaddr));
		    
	    return fill_dhcp_reply(request, reply, NULL, DHCP_NAK);
	}

    } else if (server_id != 0) { // answer to the offer of another server

	log_info("Clearing %s of %s, accepted another server offer",
		 str_ip(binding->address), str_mac(request->hdr.chaddr));
		    
	binding->status = EMPTY;
	binding->lease_time = 0;
	
	return 0;

    }

    // malformed request...
    return 0;
}

int
serve_dhcp_decline (dhcp_msg *request, dhcp_msg *reply)
{
    address_binding *binding = search_binding(&pool.bindings, request->hdr.chaddr,
					      request->hdr.hlen, STATIC_OR_DYNAMIC, PENDING);

    if(binding != NULL) {
	log_info("Declined %s by %s",
		 str_ip(binding->address), str_mac(request->hdr.chaddr));

	binding->status = EMPTY;
    }

    return 0;
}

int
serve_dhcp_release (dhcp_msg *request, dhcp_msg *reply)
{
    address_binding *binding = search_binding(&pool.bindings, request->hdr.chaddr,
					      request->hdr.hlen, STATIC_OR_DYNAMIC, ASSOCIATED);

    if(binding != NULL) {
	log_info("Released %s by %s",
		 str_mac(request->hdr.chaddr), str_ip(binding->address));

	binding->status = RELEASED;
    }

    return 0;
}

int
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

	if((len = recvfrom(s, &request.hdr, sizeof(request.hdr), 0, (struct sockaddr *)&client_sock, &slen)) < DHCP_HEADER_SIZE + 5) {
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

	case DHCP_DISCOVER:
            type = serve_dhcp_discover(&request, &reply);
	    break;

	case DHCP_REQUEST:
	    type = serve_dhcp_request(&request, &reply);
	    break;
	    
	case DHCP_DECLINE:
	    type = serve_dhcp_decline(&request, &reply);
	    break;
	    
	case DHCP_RELEASE:
	    type = serve_dhcp_release(&request, &reply);
	    break;
	    
	case DHCP_INFORM:
	    type = serve_dhcp_inform(&request, &reply);
	    break;
	    
	default:
	    printf("%s.%u: request with invalid DHCP message type option\n",
		   inet_ntoa(client_sock.sin_addr), ntohs(client_sock.sin_port));
	    break;
	
	}

	if(type != 0)
	    send_dhcp_reply(s, &client_sock, &reply);

	delete_option_list(&request.opts);
	delete_option_list(&reply.opts);

    }

}

int
main (int argc, char *argv[])
{
    int s;
    struct protoent *pp;
    struct servent *ss;
    struct sockaddr_in server_sock;

    /* Initialize global pool */

    memset(&pool, 0, sizeof(pool));

    init_binding_list(&pool.bindings);
    init_option_list(&pool.options);

    /* Load configuration */

    parse_args(argc, argv, &pool);

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
