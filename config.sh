#!/bin/bash

INTERFACE='eth0'

# get IP address (of the DHCP server) cofigured on the specified interface
IP_ADDRESS=`ifconfig $INTERFACE | awk '/inet /{ print $2 }'`

# get network mask
NETWORK_MASK=`ifconfig $INTERFACE | awk '/netmask /{ print $4 }'`

# get default gateway router
DEFAULT_GATEWAY=`route -n | grep $INTERFACE | awk '/UG/{print $2}'`

# user defined pool of addresses
POOL_START='192.168.1.50'
POOL_END='192.168.1.99'

# default duration of the lease (in seconds)
DEFAULT_LEASE_TIME='1800'

# max acceptable lease time requested by a client (in seconds)
MAX_LEASE_TIME='3600'

# how long to consider an offered address in the pending state (in seconds)
PENDING_TIME='30'
