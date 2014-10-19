#!/bin/bash

# load server configuration
. config.sh

# load static bindings
for i in static/*.sh; do
    . "$i" # TODO: prefix each option with the client id...
done

# save list of static bindings
STATIC_BINDINGS=`basename -a -s .sh static/* | tr '\n' '/'`

./dhcpserver
