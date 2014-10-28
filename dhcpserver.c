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

#include "dhcp.h"
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

// binding flags
enum {
    PENDING = 1,  // offered to client, waiting request
    STATIC = 2    // configured as a static binding
};

struct address_binding {
    uint32_t address;     // address
    uint8_t cident_len;   // client identifier len
    uint8_t cident[256];  // client identifier
    
    time_t assoc_time;    // time of association
    time_t lease_time;    // duration of lease

    int status;           // binding status
    int flags;            // binding flags

    struct address_binding *next; // next address in list
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

struct {
    uint32_t server_id; // this server id (IP address)
    uint32_t netmask;   // network mask
    uint32_t gateway;   // network gateway

    uint32_t first;     // first address of the pool
    uint32_t last;      // last address of the pool
    uint32_t current;   // current unallocated address

    time_t default_lease_time; // default duration of a lease
    time_t max_lease_time;     // max acceptable lease time
    time_t pending_time;       // duration of a binding in the pending state

    dhcp_option options[256]; // options for this pool

    address_binding *bindings; // list of associated addresses
} pool;

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
    
    address_binding *tmp = pool.bindings;
    
    if (tmp == NULL) {
	pool.bindings = binding;
    }

    else {
	while (tmp->next) tmp = tmp->next;
	tmp->next = binding;
    }

    return binding;
}

/*
 * Delete a binding
 */

void release_binding (uint8_t len, uint8_t *cident)
{
    address_binding *tmp = pool.bindings;
    
    if (tmp == NULL) {
	return;
    }

    else if (tmp->cident_len == len &&
	     memcmp(tmp->cident, cident, len) == 0) {
	pool.bindings = tmp->next;
	free(tmp);
    }

    else {
	address_binding *prev = tmp;
	tmp = tmp->next;

	while (tmp && tmp->cident_len == len &&
	       memcmp(tmp->cident, cident, len) != 0) {
	    prev = tmp;
	    tmp = tmp->next;
	}
	
	if (tmp == NULL) return;

	prev->next = tmp->next;
	free (tmp);
    }
}

/*
 * Utilities
 */

int parse_mac (char *s, void **p)
{
    *p = malloc(6);
    int i;

    if (strlen(s) != 17 ||
       s[2] != ':' || s[5] != ':' || s[8] != ':' || s[11] != ':' || s[14] != ':') {
	free(*p);
	return 0; // error: invalid MAC address
    }

    if (!isxdigit(s[0]) || !isxdigit(s[1]) || !isxdigit(s[3]) || !isxdigit(s[4]) || 
	!isxdigit(s[6]) || !isxdigit(s[7]) || !isxdigit(s[9]) || !isxdigit(s[10]) ||
	!isxdigit(s[12]) || !isxdigit(s[13]) || !isxdigit(s[15]) || !isxdigit(s[16])) {
	free(*p);
	return NULL; // error: invalid MAC address
    }

    for (i = 0; i < 6; i++) {
	long b = strtol(s+(3*i), NULL, 16);
	((uint8_t *) *p)[i] = (uint8_t) b;
    }

    return 6;
}

/* parsers for config files */

enum {
    MAX_LINE = 2048
};

enum {
    IP_ADDRESS,
    POOL_START,
    POOL_END,
    MAX_LEASE_TIME,
    PENDING_TIME
};

char *dhcp_config_names[3] = {
    [IP_ADDRESS] "IP_ADDRESS",
    [POOL_START] "POOL_START",
    [POOL_END] "POOL_END",
    [MAX_LEASE_TIME] "MAX_LEASE_TIME"
    [PENDING_TIME] "PENDING_TIME"
};

/*
 *  Token parser
 *  
 *  A token can be:
 *  - a string, enclosed in double quotes (e.g. "foobar")
 *  - a "function" name indicating the type of the data in parens
 *    (e.g. ip(127.0.0.1), mac(00:00:00:00:00:00), etc...)
 *  - an option identifier (e.g. POLICY_FILTER ...)
 * 
 *  Like strtok(3) only the FIRST TIME in_str must be not null.
 *
 *  Returned token must be free()d.
 */
char *get_token(char *in_str)
{
    static char *str = NULL;
    static int i=0;

    if (in_str) { //reset
        str = in_str;
        i = 0;
    }

    int start=i, j;
    while (str && str[i]) {

        switch (str[i]) {
            case '\n':
            case '\t':
            case '\r':
            case '(':
            case ')':
            case ' ':
                if (start!=i) return strndup(str + start, i - start);
                start++;
                i++;
                break;

            case '"':
                if (start!=i) return strndup(str + start, i - start);
                for (j=1; str[i+j] && str[i+j] != '"'; j++); // read quoted string
                i += j+1;
                return strndup(str + start + 1, j - 1);

            default:
                i++;
        }
    }

    if (start!=i) return strndup(str + start, i - start);

    return NULL;
}

/* 
 * parse input line
 *
 * returned value must be freed with free_parsed_line()
 */
char **parse_line(char *line)
{
    int len=10, count=0;
    char **tokens = malloc(len * sizeof(char *));

    tokens[count] = get_token(line);
    count++;

    while (tokens[count] = get_token(NULL)) {
        count++;

        if(count >= len) {
            len *= 2;
            tokens = realloc(tokens, len * sizeof(char *));
        }
    }

    return tokens;
}

/* free parsed line */
void free_parsed_line(char **tokens)
{
    int i;
    for (i=0; tokens[i]; i++) free(tokens[i]);
    free(tokens);
}



/* return the option number if token is a config option
   otherwise return -1 */
int token_is_dhcp_config (char *token)
{
    int i;

    for (i=0; i < 256; i++) {
	if (!strcmp(token, dhcp_config_names[i])) {
	    return i;
	}
    }

    return -1;
}

/* return the option number if token is a DHCP option
   otherwise return -1 */
int token_is_dhcp_option (char *token)
{
    int i;

    for (i=0; i < 256; i++) {
	if (!strcmp(token, dhcp_option_names[i])) {
	    return i;
	}
    }

    return -1;
}

/*
 * Functions to load cofiguration
 */

int set_ip_from_config (char *option_name, uint32_t *dst, char *option_file)
{
    uint32_t n; char *s;

    if (!(s = getenv(option_name))) {
	error("Option not specified: check %s in %s", option_name, option_file);
	return 0;
    }

    if ((n = inet_addr(s)) == INADDR_NONE) {
	error("Invalid IP address: check %s in %s", option_name, option_file);
	return 0;
    }

    *dst = ntohl(n);

    return 1;
}

int set_time_from_config (char *option_name, time_t *dst, char *option_file)
{
    char *s;

    if (!(s = getenv(option_name))) {
	error("Option not specified: check %s in %s", option_name, option_file);
	return 0;
    }

    *dst = atoi(s);

    return 1;
}

void load_global_config ()
{
    // save server IP address

    if (!set_ip_from_config("IP_ADDRESS", &pool.server_id, "config.sh"))
	exit(1);


    // save first IP address of the pool

    if (!set_ip_from_config("POOL_START", &pool.first, "config.sh"))
	exit(1);

    pool.current = pool.first;

    // save last IP address of the pool

    if (!set_ip_from_config("POOL_END", &pool.last, "config.sh"))
	exit(1);

    // save max lease time

    if (!set_time_from_config("MAX_LEASE_TIME", &pool.max_lease_time, "config.sh"))
	exit(1);

    // save pending time

    if (!set_time_from_config("PENDING_TIME", &pool.pending_time, "config.sh"))
	exit(1);

}

void load_static_bindings ()
{
    uint32_t n; char *s;

    // get list of static bindings

    if (!(s = getenv("STATIC_BINDINGS"))) {
	error("Could not obtain list of static bindings: check STATIC_BINDINGS in launch_server.sh");
	exit(1);
    }

    // for every static binding

    s = strdup(s);

    char *binding_name = strtok(s, "/");

    while(binding_name != NULL) {

	char file_name[256];
	char var_name[256];
	uint8_t mac;

	snprintf(file_name, sizeof(file_name), "%s.sh", binding_name);

	if ((mac = parse_mac(binding_name)) == NULL) {
	  error("Client identifier is not a MAC address: '%s'", binding_name);
	  exit(1);
	}

	// create binding
	address_binding *binding = add_binding (0, mac, EMPTY, STATIC);

	free(mac);

	// save IP address

	snprintf(var_name, sizeof(var_name), "%s_%s", binding_name, "IP_ADDRESS");

	if (!set_ip_from_config(var_name, &binding.address, file_name))
	    exit(1);

	// save max lease time

	snprintf(var_name, sizeof(var_name), "%s_%s", binding_name, "MAX_LEASE_TIME");
	set_time_from_config(var_name, &binding.max_lease_time, file_name);

	// save pending time

	snprintf(var_name, sizeof(var_name), "%s_%s", binding_name, "PENDING_TIME");
	set_time_from_config(var_name, &binding.pending_time, file_name);
	
	binding_name = strtok(NULL, " ");
    }

    free(s);

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
