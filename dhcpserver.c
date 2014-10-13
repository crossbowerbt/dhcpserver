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

char *option_names[256] = {

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

typedef struct dhcp_option_ {
    uint8_t id;        // option id
    uint8_t len;       // option length
    uint8_t data[256]; // option data

    struct dhcp_option_ *next; // next option in list
} dhcp_option;

/* Single address association */

typedef struct address_assoc_ {
    uint32_t address;   // address
    uint8_t chaddr[16]; // client hw address
    time_t assoc_time;  // time of association
    time_t expire_time; // time of expiration

    struct address_assoc_ *next; // next address in list
} address_assoc;

/* Address pool */

typedef struct {
    uint32_t first;   // first address of the pool
    uint32_t last;    // last address of the pool
    uint32_t current; // current unallocated address

    dhcp_option *options; // options for this pool

    address_assoc *allocated; // list of allocated addresses
    address_assoc *pending;   // list of pending addresses
} address_pool;

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
