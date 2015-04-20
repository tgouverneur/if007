client.c
========


This open a tap device and sniff it to forward every packets to one of the two specified peer. (one packet per peer each two processed packet)
Secondly, it listen on two other port and inject every packet received on theses ports on the tap device.

server.c
========


This is just doing the opposite of client.c with some differences (IIRC :P)

This is just a POC for me myself and I, it should be rewritten if used.


This code is totally bloated, contains flaws, and hasn't been re-read since it has been written,
you should not use it.
