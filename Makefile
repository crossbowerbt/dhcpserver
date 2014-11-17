CC     = gcc
CFLAGS = -Wall
OBJS   = args.o bindings.o dhcpserver.o options.o

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

dhcpserver: $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f $(OBJS) dhcpserver
