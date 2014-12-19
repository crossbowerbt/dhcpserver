DHCP Server
==========

A stand-alone DHCP server, implemented as an attempt to better grasp the chaos which is the current descendant of the good ol' BOOTP.

Implemented in pure C, no dependencies. Still in beta :)

Usage
-----

You can either launch the binary file directly, specifying all the required options, or use the launch_server.sh script, that also includes the configuration.

Configuration
-------------

Portability was one of the objectives I had in mind while writing the code.

Since system and library calls used to retrieve informations (such as MAC addresses, IP addresses and other network-related stuff) differ greatly between *linux, *bsd and other unix-like systems, I decided to "outsource" them into a shell script.

The launch_server.sh contains all the configuration the server requires to run. Give a look at it, and you will understand how to use the program and how to configure it...

License
-------

Copyright 2014 - Emanuele Acri

Offer me a coffee license: use the code as you wish, but offer me a coffee :)


