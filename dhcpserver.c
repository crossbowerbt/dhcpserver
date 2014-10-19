#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <ctype.h>

enum op_types {
    BOOTREQUEST = 1,
    BOOTREPLY   = 2,   
};

enum dhcp_message_type {
    DHCPDISCOVER = 1, /* Client broadcast to locate available servers. */
    DHCPOFFER,        /* Server to client in response to DHCPDISCOVER with
                         offer of configuration parameters. */
    DHCPREQUEST,      /* Client message to servers either (a) requesting
                         offered parameters from one server and implicitly
                         declining offers from all others, (b) confirming
                         correctness of previously allocated address after,
                         e.g., system reboot, or (c) extending the lease on a
                         particular network address */
    DHCPACK,          /* Server to client with configuration parameters,
                         including committed network address. */
    DHCPNAK,          /* Server to client indicating client's notion of network
                         address is incorrect (e.g., client has moved to new
                         subnet) or client's lease as expired */
    DHCPDECLINE,      /* Client to server indicating network address is already
                         in use. */
    DHCPRELEASE,      /* Client to server relinquishing network address and
                         cancelling remaining lease. */
    DHCPINFORM,       /* Client to server, asking only for local configuration
                         parameters; client already has externally configured
                         network address. */
};

/* DHCP message */

typedef struct {
    uint8_t op;      // message op code, message type
    uint8_t htype;   // hardware address type
    uint8_t hlen;    // hardware address length
    uint8_t hops;    // incremented by relay agents

    uint32_t xid;    // transaction ID

    uint16_t secs;   // seconds since address acquisition or renewal
    uint16_t flags;  // flags

    uint32_t ciaddr; // client IP address
    uint32_t yiaddr; // 'your' client IP address
    uint32_t siaddr; // IP address of the next server to use in bootstrap
    uint32_t giaddr; // relay agent IP address

    uint8_t chaddr[16]; // client hardware address

    uint8_t sname[64]; // server host name

    uint8_t file[128]; // boot file name

    uint8_t options[312]; // optional parameters field
} dhcp_message;

/*
 * Code ID of DHCP and BOOTP options 
 * as defined in RFC 2132
 */

enum {

/* RFC 1497 Vendor Extensions */

    PAD = 0,
    END = 255,

    SUBNET_MASK = 1,
    TIME_OFFSET = 2,
    ROUTER = 3,
    TIME_SERVER = 4,
    NAME_SERVER = 5,
    DOMAIN_NAME_SERVER = 6,
    LOG_SERVER = 7,
    COOKIE_SERVER = 8,
    LPR_SERVER = 9,
    IMPRESS_SERVER = 10,
    RESOURCE_LOCATION_SERVER = 11,
    HOST_NAME = 12,
    BOOT_FILE_SIZE = 13,
    MERIT_DUMP_FILE = 14,
    DOMAIN_NAME = 15,
    SWAP_SERVER = 16,
    ROOT_PATH = 17,
    EXTENSIONS_PATH = 18,

/* IP Layer Parameters per Host */

    IP_FORWARDING = 19,
    NON_LOCAL_SOURCE_ROUTING = 20,
    POLICY_FILTER = 21,
    MAXIMUM_DATAGRAM_REASSEMBLY_SIZE = 22,
    DEFAULT_IP_TIME_TO_LIVE = 23,
    PATH_MTU_AGING_TIMEOUT = 24,
    PATH_MTU_PLATEAU_TABLE = 25,

/* IP Layer Parameters per Interface */

    INTERFACE_MTU = 26,
    ALL_SUBNETS_ARE_LOCAL = 27,
    BROADCAST_ADDRESS = 28,
    PERFORM_MASK_DISCOVERY = 29,
    MASK_SUPPLIER = 30,
    PERFORM_ROUTER_DISCOVERY = 31,
    ROUTER_SOLICITATION_ADDRESS = 32,
    STATIC_ROUTE = 33,

/* Link Layer Parameters per Interface */

    TRAILER_ENCAPSULATION = 34,
    ARP_CACHE_TIMEOUT = 35,
    ETHERNET_ENCAPSULATION = 36,

/* TCP Parameters */

    TCP_DEFAULT_TTL = 37,
    TCP_KEEPALIVE_INTERVAL = 38,
    TCP_KEEPALIVE_GARBAGE = 39,

/* Application and Service Parameters */

    NETWORK_INFORMATION_SERVICE_DOMAIN = 40,
    NETWORK_INFORMATION_SERVERS = 41,
    NETWORK_TIME_PROTOCOL_SERVERS = 42,
    VENDOR_SPECIFIC_INFORMATION = 43,
    NETBIOS_OVER_TCP_IP_NAME_SERVER = 44,
    NETBIOS_OVER_TCP_IP_DATAGRAM_DISTRIBUTION_SERVER = 4,
    NETBIOS_OVER_TCP_IP_NODE_TYPE = 46,
    NETBIOS_OVER_TCP_IP_SCOPE = 47,
    X_WINDOW_SYSTEM_FONT_SERVER = 48,
    X_WINDOW_SYSTEM_DISPLAY_MANAGER = 49,
    NETWORK_INFORMATION_SERVICE_PLUS_DOMAIN = 64,
    NETWORK_INFORMATION_SERVICE_PLUS_SERVERS = 65,
    MOBILE_IP_HOME_AGENT = 68,
    SMTP_SERVER = 69,
    POP3_SERVER = 70,
    NNTP_SERVER = 71,
    DEFAULT_WWW_SERVER = 72,
    DEFAULT_FINGER_SERVER = 73,
    DEFAULT_IRC_SERVER = 74,
    STREETTALK_SERVER = 75,
    STREETTALK_DIRECTORY_ASSISTANCE_SERVER = 76,

/* DHCP Extensions */

    REQUESTED_IP_ADDRESS = 50,
    IP_ADDRESS_LEASE_TIME = 51,
    OPTION_OVERLOAD = 52,
    TFTP_SERVER_NAME = 66,
    BOOTFILE_NAME = 67,
    DHCP_MESSAGE_TYPE = 53,
    SERVER_IDENTIFIER = 54,
    PARAMETER_REQUEST_LIST = 55,
    MESSAGE = 56,
    MAXIMUM_DHCP_MESSAGE_SIZE = 57,
    RENEWAL_T1_TIME_VALUE = 58,
    REBINDING_T2_TIME_VALUE = 59,
    VENDOR_CLASS_IDENTIFIER = 60,
    CLIENT_IDENTIFIER = 61

};

char *dhcp_option_names[256] = {

    [PAD] "PAD",
    [END] "END",
    [SUBNET_MASK] "SUBNET_MASK",
    [TIME_OFFSET] "TIME_OFFSET",
    [ROUTER] "ROUTER",
    [TIME_SERVER] "TIME_SERVER",
    [NAME_SERVER] "NAME_SERVER",
    [DOMAIN_NAME_SERVER] "DOMAIN_NAME_SERVER",
    [LOG_SERVER] "LOG_SERVER",
    [COOKIE_SERVER] "COOKIE_SERVER",
    [LPR_SERVER] "LPR_SERVER",
    [IMPRESS_SERVER] "IMPRESS_SERVER",
    [RESOURCE_LOCATION_SERVER] "RESOURCE_LOCATION_SERVER",
    [HOST_NAME] "HOST_NAME",
    [BOOT_FILE_SIZE] "BOOT_FILE_SIZE",
    [MERIT_DUMP_FILE] "MERIT_DUMP_FILE",
    [DOMAIN_NAME] "DOMAIN_NAME",
    [SWAP_SERVER] "SWAP_SERVER",
    [ROOT_PATH] "ROOT_PATH",
    [EXTENSIONS_PATH] "EXTENSIONS_PATH",
    [IP_FORWARDING] "IP_FORWARDING",
    [NON_LOCAL_SOURCE_ROUTING] "NON_LOCAL_SOURCE_ROUTING",
    [POLICY_FILTER] "POLICY_FILTER",
    [MAXIMUM_DATAGRAM_REASSEMBLY_SIZE] "MAXIMUM_DATAGRAM_REASSEMBLY_SIZE",
    [DEFAULT_IP_TIME_TO_LIVE] "DEFAULT_IP_TIME_TO_LIVE",
    [PATH_MTU_AGING_TIMEOUT] "PATH_MTU_AGING_TIMEOUT",
    [PATH_MTU_PLATEAU_TABLE] "PATH_MTU_PLATEAU_TABLE",
    [INTERFACE_MTU] "INTERFACE_MTU",
    [ALL_SUBNETS_ARE_LOCAL] "ALL_SUBNETS_ARE_LOCAL",
    [BROADCAST_ADDRESS] "BROADCAST_ADDRESS",
    [PERFORM_MASK_DISCOVERY] "PERFORM_MASK_DISCOVERY",
    [MASK_SUPPLIER] "MASK_SUPPLIER",
    [PERFORM_ROUTER_DISCOVERY] "PERFORM_ROUTER_DISCOVERY",
    [ROUTER_SOLICITATION_ADDRESS] "ROUTER_SOLICITATION_ADDRESS",
    [STATIC_ROUTE] "STATIC_ROUTE",
    [TRAILER_ENCAPSULATION] "TRAILER_ENCAPSULATION",
    [ARP_CACHE_TIMEOUT] "ARP_CACHE_TIMEOUT",
    [ETHERNET_ENCAPSULATION] "ETHERNET_ENCAPSULATION",
    [TCP_DEFAULT_TTL] "TCP_DEFAULT_TTL",
    [TCP_KEEPALIVE_INTERVAL] "TCP_KEEPALIVE_INTERVAL",
    [TCP_KEEPALIVE_GARBAGE] "TCP_KEEPALIVE_GARBAGE",
    [NETWORK_INFORMATION_SERVICE_DOMAIN] "NETWORK_INFORMATION_SERVICE_DOMAIN",
    [NETWORK_INFORMATION_SERVERS] "NETWORK_INFORMATION_SERVERS",
    [NETWORK_TIME_PROTOCOL_SERVERS] "NETWORK_TIME_PROTOCOL_SERVERS",
    [VENDOR_SPECIFIC_INFORMATION] "VENDOR_SPECIFIC_INFORMATION",
    [NETBIOS_OVER_TCP_IP_NAME_SERVER] "NETBIOS_OVER_TCP_IP_NAME_SERVER",
    [NETBIOS_OVER_TCP_IP_DATAGRAM_DISTRIBUTION_SERVER] "NETBIOS_OVER_TCP_IP_DATAGRAM_DISTRIBUTION_SERVER",
    [NETBIOS_OVER_TCP_IP_NODE_TYPE] "NETBIOS_OVER_TCP_IP_NODE_TYPE",
    [NETBIOS_OVER_TCP_IP_SCOPE] "NETBIOS_OVER_TCP_IP_SCOPE",
    [X_WINDOW_SYSTEM_FONT_SERVER] "X_WINDOW_SYSTEM_FONT_SERVER",
    [X_WINDOW_SYSTEM_DISPLAY_MANAGER] "X_WINDOW_SYSTEM_DISPLAY_MANAGER",
    [NETWORK_INFORMATION_SERVICE_PLUS_DOMAIN] "NETWORK_INFORMATION_SERVICE_PLUS_DOMAIN",
    [NETWORK_INFORMATION_SERVICE_PLUS_SERVERS] "NETWORK_INFORMATION_SERVICE_PLUS_SERVERS",
    [MOBILE_IP_HOME_AGENT] "MOBILE_IP_HOME_AGENT",
    [SMTP_SERVER] "SMTP_SERVER",
    [POP3_SERVER] "POP3_SERVER",
    [NNTP_SERVER] "NNTP_SERVER",
    [DEFAULT_WWW_SERVER] "DEFAULT_WWW_SERVER",
    [DEFAULT_FINGER_SERVER] "DEFAULT_FINGER_SERVER",
    [DEFAULT_IRC_SERVER] "DEFAULT_IRC_SERVER",
    [STREETTALK_SERVER] "STREETTALK_SERVER",
    [STREETTALK_DIRECTORY_ASSISTANCE_SERVER] "STREETTALK_DIRECTORY_ASSISTANCE_SERVER",
    [REQUESTED_IP_ADDRESS] "REQUESTED_IP_ADDRESS",
    [IP_ADDRESS_LEASE_TIME] "IP_ADDRESS_LEASE_TIME",
    [OPTION_OVERLOAD] "OPTION_OVERLOAD",
    [TFTP_SERVER_NAME] "TFTP_SERVER_NAME",
    [BOOTFILE_NAME] "BOOTFILE_NAME",
    [DHCP_MESSAGE_TYPE] "DHCP_MESSAGE_TYPE",
    [SERVER_IDENTIFIER] "SERVER_IDENTIFIER",
    [PARAMETER_REQUEST_LIST] "PARAMETER_REQUEST_LIST",
    [MESSAGE] "MESSAGE",
    [MAXIMUM_DHCP_MESSAGE_SIZE] "MAXIMUM_DHCP_MESSAGE_SIZE",
    [RENEWAL_T1_TIME_VALUE] "RENEWAL_T1_TIME_VALUE",
    [REBINDING_T2_TIME_VALUE] "REBINDING_T2_TIME_VALUE",
    [VENDOR_CLASS_IDENTIFIER] "VENDOR_CLASS_IDENTIFIER",
    [CLIENT_IDENTIFIER] "CLIENT_IDENTIFIER"
    
};

uint8_t option_magic[4] = { 0x63, 0x82, 0x53, 0x63 };

typedef struct dhcp_option_ {
    uint8_t id;        // option id
    uint8_t len;       // option length
    uint8_t data[256]; // option data

    struct dhcp_option_ *next; // next option in list
} dhcp_option;

/* Single address association */

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

typedef struct address_binding_ {
    uint32_t address;     // address
    uint8_t chaddr[16];   // client hw address
    uint8_t cident[256];  // client identifier
    
    time_t assoc_time;    // time of association
    time_t expire_time;   // time of expiration
    int status;           // binding status
    int flags;            // binding flags

    dhcp_option *options; // options for this association

    struct address_binding_ *next; // next address in list
} address_binding;

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

    dhcp_option *options; // options for this pool

    address_binding *bindings; // list of associated addresses
} pool;

/* Option-related function */

uint8_t *serialize_option (uint8_t *p, dhcp_option *o)
{
    p[0] = o->id;
    p[1] = o->len;
    memcpy(p+2, o->data, o->len);

    return p + 2 + o->len;
}

/* parsers for config files */

void * parse_long (char *s)
{
    long *l = malloc(sizeof(*l));
    l = strtol(s, NULL, 0);
    return l;
}

void * parse_string (char *s)
{
    return strdup(s);
}

void * parse_ip (char *s)
{
    struct sockaddr_in *ip = malloc(sizeof(*ip));

    if (inet_aton(s, &ip->sin_addr) == 0) { // error: invalid IP address
	free(ip);
	return NULL;
    }

    return ip;
}

void * parse_mac (char *s)
{
    uint8_t *mac = malloc(6);
    int i;

    if (strlen(s) != 17 ||
       s[2] != ':' || s[5] != ':' || s[8] != ':' || s[11] != ':' || s[14] != ':') {
	free(mac);
	return NULL; // error: invalid MAC address
    }

    if (!isxdigit(s[0]) || !isxdigit(s[1]) || !isxdigit(s[3]) || !isxdigit(s[4]) || 
	!isxdigit(s[6]) || !isxdigit(s[7]) || !isxdigit(s[9]) || !isxdigit(s[10]) ||
	!isxdigit(s[12]) || !isxdigit(s[13]) || !isxdigit(s[15]) || !isxdigit(s[16])) {
	free(mac);
	return NULL; // error: invalid MAC address
    }

    for (i = 0; i < 6; i++) {
	long b = strtol(s+(3*i), NULL, 16);
	mac[i] = (uint8_t) b;
    }

    mac;
}

enum {
    MAX_LINE = 2048
};

enum {
    IP_ADDRESS,
    NETWORK_MASK,
    DEFAULT_ROUTER,
    POOL_START,
    POOL_END,
    DEFAULT_LEASE_TIME,
    MAX_LEASE_TIME,
    PENDING_TIME
};

char *dhcp_config_names[3] = {
    [IP_ADDRESS] "IP_ADDRESS",
    [NETWORK_MASK] "NETWORK_MASK",
    [DEFAULT_ROUTER] "DEFAULT_ROUTER",    
    [POOL_START] "POOL_START",
    [POOL_END] "POOL_END",
    [DEFAULT_LEASE_TIME] "DEFAULT_LEASE_TIME"
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

void load_global_config ()
{
    uint32_t n; char *s;

    // save server IP address

    if (!(s = getenv("IP_ADDRESS"))) {
	error("Could not obtain server IP address: check IP_ADDRESS in config.sh");
	exit(1);
    }

    if ((n = inet_addr(s)) == INADDR_NONE) {
	error("Invalid server IP address: check IP_ADDRESS in config.sh");
	exit(1);
    }

    pool.server_id = ntohl(n);

    // save network mask

    if (!(s = getenv("NETWORK_MASK"))) {
	error("Could not obtain network mask: check NETWORK_MASK in config.sh");
	exit(1);
    }

    if ((n = inet_addr(s)) == INADDR_NONE) {
	error("Invalid network mask: check NETWORK_MASK in config.sh");
	exit(1);
    }

    pool.netmask = ntohl(n);

    // save default gateway

    if (!(s = getenv("DEFAULT_GATEWAY"))) {
	error("Could not obtain default gateway: check DEFAULT_GATEWAY in config.sh");
	exit(1);
    }

    if ((n = inet_addr(s)) == INADDR_NONE) {
	error("Invalid default gateway: check DEFAULT_GATEWAY in config.sh");
	exit(1);
    }

    pool.gateway = ntohl(n);

    // save first IP address of the pool

    if (!(s = getenv("POOL_START"))) {
	error("Could not obtain first IP address of the pool: check POOL_START in config.sh");
	exit(1);
    }

    if ((n = inet_addr(s)) == INADDR_NONE) {
	error("Invalid first IP address of the pool: check POOL_START in config.sh");
	exit(1);
    }

    pool.first = ntohl(n);
    pool.current = pool.first;

    // save last IP address of the pool

    if (!(s = getenv("POOL_END"))) {
	error("Could not obtain last IP address of the pool: check POOL_END in config.sh");
	exit(1);
    }

    if ((n = inet_addr(s)) == INADDR_NONE) {
	error("Invalid last IP address of the pool: check POOL_END in config.sh");
	exit(1);
    }

    pool.last = ntohl(n);

    // save default lease time

    if (!(s = getenv("DEFAULT_LEASE_TIME"))) {
	error("Could not obtain default lease time: check DEFAULT_LEASE_TIME in config.sh");
	exit(1);
    }

    pool.default_lease_time = atoi(s);

    // save max lease time

    if (!(s = getenv("MAX_LEASE_TIME"))) {
	error("Could not obtain max lease time: check MAX_LEASE_TIME in config.sh");
	exit(1);
    }

    pool.max_lease_time = atoi(s);

    // save pending time

    if (!(s = getenv("PENDING_TIME"))) {
	error("Could not obtain pending time: check PENDING_TIME in config.sh");
	exit(1);
    }

    pool.pending_time = atoi(s);

}

/*
 * DHCP server functions
 */

dhcp_message *serve_dhcp_discover (dhcp_message *msg, dhcp_option *opts)
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

dhcp_message *serve_dhcp_request (dhcp_message *msg, dhcp_option *opts)
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

dhcp_message *serve_dhcp_decline (dhcp_message *msg, dhcp_option *opts)
{
    dhcp_binding binding = search_pending_binding(msg);

    log_error("Declined address by '%s' of address '%s'",
	      str_mac(msg->chaddr), str_ip(assoc->address));

    release_binding(binding);

    return NULL;
}

3dhcp_message *serve_dhcp_release (dhcp_message *msg, dhcp_option *opts)
{
    dhcp_binding binding = search_pending_binding(msg);

    log_info("Released address by '%s' of address '%s'",
	      str_mac(msg->chaddr), str_ip(assoc->address));

    release_binding(binding);

    return NULL;
}

dhcp_message *serve_dhcp_inform (dhcp_message *msg, dhcp_option *opts)
{
    // TODO

    return NULL;
}

int main (int argc, char *argv[])
{
    int s;
    uint16_t port;
    struct protoent *pp;
    struct servent *ss;
    struct sockaddr_in server_sock;

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

     while (1) {
         struct sockaddr_in client_sock;
         socklen_t slen = sizeof(client_sock);
         ssize_t len;

         dhcp_message message;
         uint8_t opcode;

         if ((len = dhcp_recv_message(s, &message, &client_sock, &slen)) < 0) {
             continue;
         }

         if (len < 300) { 
             printf("%s.%u: request with invalid size received\n",
                    inet_ntoa(client_sock.sin_addr), ntohs(client_sock.sin_port));
             dhcp_send_error(s, 0, "invalid request size", &client_sock, slen);
             continue;
         }

          opcode = message.op;

          if (opcode == RRQ || opcode == WRQ) {

               /* spawn a child process to handle the request */

               if (fork() == 0) {
                    tftp_handle_request(&message, len, &client_sock, slen);
                    exit(0);
               }

          }

          else {
               printf("%s.%u: invalid request received: opcode \n", 
                      inet_ntoa(client_sock.sin_addr), ntohs(client_sock.sin_port),
                      opcode);
               tftp_send_error(s, 0, "invalid opcode", &client_sock, slen);
          }

     }

     close(s);

     return 0;
}