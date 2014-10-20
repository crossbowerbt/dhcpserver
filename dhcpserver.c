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
#include <regex.h>

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

enum {
    DHCP_HEADER_SIZE = 236 // without size of options
};

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

struct {
    char *name;
    (int (*f)) (char *, void **);
} dhcp_option_info [256] = {

    [PAD] { "PAD", NULL },
    [END] { "END", NULL },
    [SUBNET_MASK] { "SUBNET_MASK", parse_ip },
    [TIME_OFFSET] { "TIME_OFFSET", parse_long },
    [ROUTER] { "ROUTER", parse_ip_list },
    [TIME_SERVER] { "TIME_SERVER", parse_ip_list },
    [NAME_SERVER] { "NAME_SERVER", parse_ip_list },
    [DOMAIN_NAME_SERVER] { "DOMAIN_NAME_SERVER", parse_ip_list },
    [LOG_SERVER] { "LOG_SERVER", parse_ip_list },
    [COOKIE_SERVER] { "COOKIE_SERVER", parse_ip_list },
    [LPR_SERVER] { "LPR_SERVER", parse_ip_list },
    [IMPRESS_SERVER] { "IMPRESS_SERVER", parse_ip_list },
    [RESOURCE_LOCATION_SERVER] { "RESOURCE_LOCATION_SERVER", parse_ip_list },
    [HOST_NAME] { "HOST_NAME", parse_string },
    [BOOT_FILE_SIZE] { "BOOT_FILE_SIZE", parse_short },
    [MERIT_DUMP_FILE] { "MERIT_DUMP_FILE", parse_string },
    [DOMAIN_NAME] { "DOMAIN_NAME", parse_string },
    [SWAP_SERVER] { "SWAP_SERVER", parse_ip },
    [ROOT_PATH] { "ROOT_PATH", parse_string },
    [EXTENSIONS_PATH] { "EXTENSIONS_PATH", parse_string },
    [IP_FORWARDING] { "IP_FORWARDING", parse_byte },
    [NON_LOCAL_SOURCE_ROUTING] { "NON_LOCAL_SOURCE_ROUTING", parse_byte },
    [POLICY_FILTER] { "POLICY_FILTER", parse_ip_list },
    [MAXIMUM_DATAGRAM_REASSEMBLY_SIZE] { "MAXIMUM_DATAGRAM_REASSEMBLY_SIZE", parse_short },
    [DEFAULT_IP_TIME_TO_LIVE] { "DEFAULT_IP_TIME_TO_LIVE", parse_byte },
    [PATH_MTU_AGING_TIMEOUT] { "PATH_MTU_AGING_TIMEOUT", parse_long },
    [PATH_MTU_PLATEAU_TABLE] { "PATH_MTU_PLATEAU_TABLE", parse_short_list },
    [INTERFACE_MTU] { "INTERFACE_MTU", parse_short },
    [ALL_SUBNETS_ARE_LOCAL] { "ALL_SUBNETS_ARE_LOCAL", parse_byte },
    [BROADCAST_ADDRESS] { "BROADCAST_ADDRESS", parse_ip },
    [PERFORM_MASK_DISCOVERY] { "PERFORM_MASK_DISCOVERY", parse_byte },
    [MASK_SUPPLIER] { "MASK_SUPPLIER", parse_byte },
    [PERFORM_ROUTER_DISCOVERY] { "PERFORM_ROUTER_DISCOVERY", parse_byte },
    [ROUTER_SOLICITATION_ADDRESS] { "ROUTER_SOLICITATION_ADDRESS", parse_ip },
    [STATIC_ROUTE] { "STATIC_ROUTE", parse_ip_list },
    [TRAILER_ENCAPSULATION] { "TRAILER_ENCAPSULATION", parse_byte },
    [ARP_CACHE_TIMEOUT] { "ARP_CACHE_TIMEOUT", parse_long },
    [ETHERNET_ENCAPSULATION] { "ETHERNET_ENCAPSULATION", parse_byte },
    [TCP_DEFAULT_TTL] { "TCP_DEFAULT_TTL", parse_byte },
    [TCP_KEEPALIVE_INTERVAL] { "TCP_KEEPALIVE_INTERVAL", parse_long },
    [TCP_KEEPALIVE_GARBAGE] { "TCP_KEEPALIVE_GARBAGE", parse_byte },
    [NETWORK_INFORMATION_SERVICE_DOMAIN] { "NETWORK_INFORMATION_SERVICE_DOMAIN", parse_string },
    [NETWORK_INFORMATION_SERVERS] { "NETWORK_INFORMATION_SERVERS", parse_ip_list },
    [NETWORK_TIME_PROTOCOL_SERVERS] { "NETWORK_TIME_PROTOCOL_SERVERS", parse_ip_list },
    [VENDOR_SPECIFIC_INFORMATION] { "VENDOR_SPECIFIC_INFORMATION", parse_byte_list },
    [NETBIOS_OVER_TCP_IP_NAME_SERVER] { "NETBIOS_OVER_TCP_IP_NAME_SERVER", parse_ip_list },
    [NETBIOS_OVER_TCP_IP_DATAGRAM_DISTRIBUTION_SERVER] { "NETBIOS_OVER_TCP_IP_DATAGRAM_DISTRIBUTION_SERVER", parse_ip_list },
    [NETBIOS_OVER_TCP_IP_NODE_TYPE] { "NETBIOS_OVER_TCP_IP_NODE_TYPE", parse_byte },
    [NETBIOS_OVER_TCP_IP_SCOPE] { "NETBIOS_OVER_TCP_IP_SCOPE", parse_string },
    [X_WINDOW_SYSTEM_FONT_SERVER] { "X_WINDOW_SYSTEM_FONT_SERVER", parse_ip_list },
    [X_WINDOW_SYSTEM_DISPLAY_MANAGER] { "X_WINDOW_SYSTEM_DISPLAY_MANAGER", parse_ip_list },
    [NETWORK_INFORMATION_SERVICE_PLUS_DOMAIN] { "NETWORK_INFORMATION_SERVICE_PLUS_DOMAIN", parse_string },
    [NETWORK_INFORMATION_SERVICE_PLUS_SERVERS] { "NETWORK_INFORMATION_SERVICE_PLUS_SERVERS", parse_ip_list },
    [MOBILE_IP_HOME_AGENT] { "MOBILE_IP_HOME_AGENT", parse_ip_list },
    [SMTP_SERVER] { "SMTP_SERVER", parse_ip_list },
    [POP3_SERVER] { "POP3_SERVER", parse_ip_list },
    [NNTP_SERVER] { "NNTP_SERVER", parse_ip_list },
    [DEFAULT_WWW_SERVER] { "DEFAULT_WWW_SERVER", parse_ip_list },
    [DEFAULT_FINGER_SERVER] { "DEFAULT_FINGER_SERVER", parse_ip_list },
    [DEFAULT_IRC_SERVER] { "DEFAULT_IRC_SERVER", parse_ip_list },
    [STREETTALK_SERVER] { "STREETTALK_SERVER", parse_ip_list },
    [STREETTALK_DIRECTORY_ASSISTANCE_SERVER] { "STREETTALK_DIRECTORY_ASSISTANCE_SERVER",  parse_ip_list },
    [REQUESTED_IP_ADDRESS] { "REQUESTED_IP_ADDRESS", NULL },
    [IP_ADDRESS_LEASE_TIME] { "IP_ADDRESS_LEASE_TIME", parse_long },
    [OPTION_OVERLOAD] { "OPTION_OVERLOAD", parse_byte },
    [TFTP_SERVER_NAME] { "TFTP_SERVER_NAME", parse_string },
    [BOOTFILE_NAME] { "BOOTFILE_NAME", parse_string },
    [DHCP_MESSAGE_TYPE] { "DHCP_MESSAGE_TYPE", NULL },
    [SERVER_IDENTIFIER] { "SERVER_IDENTIFIER", parse_ip },
    [PARAMETER_REQUEST_LIST] { "PARAMETER_REQUEST_LIST", NULL },
    [MESSAGE] { "MESSAGE", NULL },
    [MAXIMUM_DHCP_MESSAGE_SIZE] { "MAXIMUM_DHCP_MESSAGE_SIZE", NULL },
    [RENEWAL_T1_TIME_VALUE] { "RENEWAL_T1_TIME_VALUE", parse_long },
    [REBINDING_T2_TIME_VALUE] { "REBINDING_T2_TIME_VALUE", parse_long },
    [VENDOR_CLASS_IDENTIFIER] { "VENDOR_CLASS_IDENTIFIER", NULL },
    [CLIENT_IDENTIFIER] { "CLIENT_IDENTIFIER", NULL },
    
};

uint8_t option_magic[4] = { 0x63, 0x82, 0x53, 0x63 };

typedef struct dhcp_option_ {
    uint8_t id;        // option id
    uint8_t len;       // option length
    uint8_t data[256]; // option data
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
    uint8_t cident_len;   // client identifier len
    uint8_t cident[256];  // client identifier
    
    time_t assoc_time;    // time of association
    time_t lease_time;    // duration of lease

    int status;           // binding status
    int flags;            // binding flags

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

/* Option-related function */

int parse_byte (char *s, void **p)
{
    *p = malloc(sizeof(uint8_t));
    **p = ((uint8_t) strtol(s, NULL, 0));

    return sizeof(uint8_t);
}

int parse_byte_list (char *s, void **p)
{
    *p = malloc(strlen(s) * sizeof(uint8_t)); // slightly over the strictly requested size

    int count = 0;

    char *s2 = strdup(s);
    char *s3 = strtok(s2, ", ");

    while(s3 != NULL) {

	uint8_t n = ((uint8_t) strtol(s3, NULL, 0));

	memcpy(((uint8_t *) *p) + count, n, sizeof(uint8_t));

	count += sizeof(uint8_t);
	s3 = strtok(NULL, " ");
    }

    free(s2);

    return count;
}

int parse_short (char *s, void **p)
{
    *p = malloc(sizeof(uint16_t));
    **p = ((uint16_t) strtol(s, NULL, 0));

    return sizeof(uint16_t);
}

int parse_short_list (char *s, void **p)
{
    *p = malloc(strlen(s) * sizeof(uint16_t)); // slightly over the strictly requested size

    int count = 0;

    char *s2 = strdup(s);
    char *s3 = strtok(s2, ", ");

    while(s3 != NULL) {

	uint16_t n = ((uint16_t) strtol(s3, NULL, 0));

	memcpy(((uint8_t *) *p) + count, n, sizeof(uint16_t));

	count += sizeof(uint16_t);
	s3 = strtok(NULL, " ");
    }

    free(s2);

    return count;
}

int parse_long (char *s, void **p)
{
    *p = malloc(sizeof(uint32_t));
    **p = strtol(s, NULL, 0);

    return sizeof(uint32_t);
}

int parse_string (char *s, void **p)
{
    *p = strdup(s);

    return strlen(s);
}

int parse_ip (char *s, void **p)
{
    struct sockaddr_in ip;
    
    *p = malloc(sizeof(uint32_t));

    if (inet_aton(s, &ip.sin_addr) == 0) { // error: invalid IP address
	free(*p);
	return 0;
    }

    memcpy(*p, ip.sin_addr, sizeof(uint32_t));

    return sizeof(uint32_t);
}

int parse_ip_list (char *s, void **p)
{
    *p = malloc(strlen(s) * sizeof(uint32_t) / 4); // slightly over the strictly required size

    int count = 0;

    char *s2 = strdup(s);
    char *s3 = strtok(s2, ", ");

    while(s3 != NULL) {
	struct sockaddr_in ip;

	if (inet_aton(s3, &ip.sin_addr) == 0) { // error: invalid IP address
	    free(*p);
	    return 0;
	}

	memcpy(((* uint8_t) *p) + count, ip.sin_addr, sizeof(uint32_t));

	count += sizeof(uint32_t);
	s3 = strtok(NULL, " ");
    }

    free(s2);

    return count;
}

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

dhcp_option * parse_option (dhcp_option *opt, char *name, char *value)
{
    (int (*f)) (char *, void **);
    int code;

    uint8_t len;
    uint8_t *p;

    for (code = 0; code < 256; code++) {
	if (dhcp_option_names[code].name &&
	    strcmp(dhcp_option_names[code].name, name) == 0) break;
    }

    if (code == 256) {
	error("Unsupported DHCP option '%s'", name);
	return NULL;
    }

    f = dhcp_option_info[code].f;

    if (f == NULL) {
	error("Unsupported DHCP option '%s'", name);
	return NULL;
    }

    len = f(value, &p);

    opt->id = id;
    opt->len = len;

    memcpy(opt->data, p, len);

    free(p);

    return opt;
}

dhcp_option * copy_option (uint8_t id, dhcp_option *opts, dhcp_option *dst)
{
    dhcp_option *opt = &opts[id];

    if (opt->id == 0)
	return NULL;

    memcpy(dst, opt, 2 + opt->len);

    // return next place to write a DHCP option
    return ((uint8_t *) dst) + 2 + opt->len;
}

dhcp_option * search_option (uint8_t id, int opts_len, dhcp_option *opts)
{
    dhcp_option *opt = opts, *end = ((uint8_t *) opts) + opts_len;

    while (opt < end && opt->id != id && opt->id != END) {
	opt = ((uint8_t *) opt) + 2 + opt->len;
    }

    if (opt < end && opt->id == id)
	return opt;

    return NULL;
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

dhcp_message *serve_dhcp_release (dhcp_message *msg, dhcp_option *opts)
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

/*
 * Dispatch client DHCP messages to the correct handling routines
 */

void message_dispatcher (sockaddr_in server_sock, int s)
{
     
    while (1) {
	struct sockaddr_in client_sock;
	socklen_t slen = sizeof(client_sock);
	ssize_t len;

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
	    serve_dhcp_discover(message, opts);

	case DHCPREQUEST:
	    serve_dhcp_request(message, opts);

	case DHCPDECLINE:
	    serve_dhcp_decline(message, opts);

	case DHCPRELEASE:
	    serve_dhcp_release(message, opts);

	case DHCPINFORM:
	    serve_dhcp_inform(message, opts);

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
