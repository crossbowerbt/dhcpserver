#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <netdb.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/errno.h>
#include <time.h>
#include <ctype.h>
#include <regex.h>

#include "options.h"
#include "logging.h"

const uint8_t option_magic[4] = { 0x63, 0x82, 0x53, 0x63 };

/* 
 * Mapping table between DHCP options and 
 * functions that parse their value.
 */

static struct {

    char *name;
    int (*f) (char *, void **);

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

/* Value parsing functions */

int
parse_byte (char *s, void **p)
{
    *p = malloc(sizeof(uint8_t));
    uint8_t n = ((uint8_t) strtol(s, NULL, 0));
    memcpy(*p, &n, sizeof(n));
    
    return sizeof(uint8_t);
}

int
parse_byte_list (char *s, void **p)
{
    *p = malloc(strlen(s) * sizeof(uint8_t)); // slightly over the strictly requested size

    int count = 0;

    char *s2 = strdup(s);
    char *s3 = strtok(s2, ", ");

    while(s3 != NULL) {

	uint8_t n = ((uint8_t) strtol(s3, NULL, 0));

	memcpy(((uint8_t *) *p) + count, &n, sizeof(uint8_t));

	count += sizeof(uint8_t);
	s3 = strtok(NULL, " ");
    }

    free(s2);

    return count;
}

int
parse_short (char *s, void **p)
{
    *p = malloc(sizeof(uint16_t));
    uint16_t n = ((uint16_t) strtol(s, NULL, 0));
    memcpy(*p, &n, sizeof(n));
    
    return sizeof(uint16_t);
}

int
parse_short_list (char *s, void **p)
{
    *p = malloc(strlen(s) * sizeof(uint16_t)); // slightly over the strictly requested size

    int count = 0;

    char *s2 = strdup(s);
    char *s3 = strtok(s2, ", ");

    while(s3 != NULL) {

	uint16_t n = ((uint16_t) strtol(s3, NULL, 0));

	memcpy(((uint8_t *) *p) + count, &n, sizeof(uint16_t));

	count += sizeof(uint16_t);
	s3 = strtok(NULL, " ");
    }

    free(s2);

    return count;
}

int
parse_long (char *s, void **p)
{
    *p = malloc(sizeof(uint32_t));
    uint32_t n = strtol(s, NULL, 0);
    memcpy(*p, &n, sizeof(n));

    return sizeof(uint32_t);
}

int
parse_string (char *s, void **p)
{
    *p = strdup(s);

    return strlen(s);
}

int
parse_ip (char *s, void **p)
{
    struct sockaddr_in ip;
    
    *p = malloc(sizeof(uint32_t));

    if (inet_aton(s, &ip.sin_addr) == 0) { // error: invalid IP address
	free(*p);
	return 0;
    }

    memcpy(*p, &ip.sin_addr, sizeof(uint32_t));

    return sizeof(uint32_t);
}

int
parse_ip_list (char *s, void **p)
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

	memcpy(((uint8_t *) *p) + count, &ip.sin_addr, sizeof(uint32_t));

	count += sizeof(uint32_t);
	s3 = strtok(NULL, " ");
    }

    free(s2);

    return count;
}

int
parse_mac (char *s, void **p)
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
	return 0; // error: invalid MAC address
    }

    for (i = 0; i < 6; i++) {
	long b = strtol(s+(3*i), NULL, 16);
	((uint8_t *) *p)[i] = (uint8_t) b;
    }

    return 6;
}

/* Option-related functions */

/* 
 * Given the name of the option and its value as strings,
 * fill the dhcp_option structure pointed by opt.
 *
 * On success return the parsed option id,
 * otherwise return zero.
 */
uint8_t
parse_option (dhcp_option *opt, char *name, char *value)
{
    int (*f) (char *, void **);
    int id;

    uint8_t len;
    uint8_t *p;

    for (id = 0; id < 256; id++) { // search the option by name
        if (dhcp_option_info[id].name &&
                strcmp(dhcp_option_info[id].name, name) == 0) break;
    }

    if (id == 256) { // not found
        log_error("Unsupported DHCP option '%s'", name);
        return 0;
    }

    f = dhcp_option_info[id].f;

    if (f == NULL) { // no parsing function available
        log_error("Unsupported DHCP option '%s'", name);
        return 0;
    }

    len = f(value, (void **)&p); // parse the value

    if(len == 0) // error parsing the value
	return 0;

    // structure filling
    opt->id = id;
    opt->len = len;
    memcpy(opt->data, p, len);

    free(p);

    return opt->id;
}

/*
 * Initialize an option list.
 */

void
init_option_list (dhcp_option_list *list)
{
    STAILQ_INIT(list);
}

/*
 * Given a list of options search an option having
 * the passed option id, and returns a pointer to it.
 *
 * If the option is not present the function returns NULL.
 */

dhcp_option *
search_option (dhcp_option_list *list, uint8_t id)
{
    dhcp_option *opt, *opt_temp;

    STAILQ_FOREACH_SAFE(opt, list, pointers, opt_temp) {

	if(opt->id == id)
	    return opt;

    }
    
    return NULL;
}

/*
 * Print options in list.
 */

void
print_options (dhcp_option_list *list)
{
    dhcp_option *opt, *opt_temp;
    int i=0;

    STAILQ_FOREACH_SAFE(opt, list, pointers, opt_temp) {

	printf("options[%d]=%d (%s)\n", i++, opt->id,
	       dhcp_option_info[opt->id].name);

    }
}


/*
 * Append the provided option to the list.
 *
 * Always allocate new memory, that must be freed later...
 */

void
append_option (dhcp_option_list *list, dhcp_option *opt)
{
    dhcp_option *nopt = calloc(1, sizeof(*nopt));
    memcpy(nopt, opt, 2 + opt->len);
    
    STAILQ_INSERT_TAIL(list, nopt, pointers);
}

/*
 * Parse the options contained in a DHCP message into a list.
 *
 * Return 1 on success, 0 if the options are malformed.
 */

int
parse_options_to_list (dhcp_option_list *list, dhcp_option *opts, size_t len)
{
    dhcp_option *opt, *end;

    opt = opts;
    end = (dhcp_option *)(((uint8_t *)opts) + len);

    if (len < 4 ||
	memcmp(opt, option_magic, sizeof(option_magic)) != 0)
	return 0;

    opt = (dhcp_option *)(((uint8_t *) opt) + 4);

    while (opt < end  &&
	   opt->id != END) { // TODO: check also valid option sizes

	if ((dhcp_option *)(((uint8_t *) opt) + 2 + opt->len) >= end)
	    return 0; // the len field is too long

	append_option(list, opt);

        opt = (dhcp_option *)(((uint8_t *) opt) + 2 + opt->len);
    }

    if (opt < end && opt->id == END)
        return 1;

    return 0;
}

/*
 * Serialize a list of options, to be inserted directly inside
 * the options section of a DHCP message.
 *
 * Return 0 on error, the total serialized len on success.
 */

size_t
serialize_option_list (dhcp_option_list *list, uint8_t *buf, size_t len)
{
    uint8_t *p = buf;

    if (len < 4)
	return 0;

    memcpy(p, option_magic, sizeof(option_magic));
    p += 4; len -= 4;

    dhcp_option *opt, *opt_temp;
    
    STAILQ_FOREACH_SAFE(opt, list, pointers, opt_temp) {

	if (len <= 2 + opt->len)
	    return 0;

	memcpy(p, opt, 2 + opt->len);
	p   += 2 + opt->len;
	len -= 2 + opt->len;
	
    }

    if (len < 1)
	return 0;

    *p = END;

    p++; len--;

    return p - buf;
}

/*
 * Delete an option list and deallocate its memory.
 * Deallocate even the list elements.
 */

void
delete_option_list (dhcp_option_list *list)
{
    dhcp_option *opt = STAILQ_FIRST(list);
    dhcp_option *tmp;
    
    while (opt != NULL) {
	tmp = STAILQ_NEXT(opt, pointers);
	free(opt);
	opt = tmp;
     }
    
    STAILQ_INIT(list);
}
