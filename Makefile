CC     = gcc
CFLAGS = -Wall -ggdb
OBJS   = args.o bindings.o dhcpserver.o options.o

.c.o:
	$(CC) -c -o $@ $< $(CFLAGS)

dhcpserver: $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f $(OBJS) dhcpserver
