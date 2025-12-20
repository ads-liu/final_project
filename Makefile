CC      := gcc
CFLAGS  := -Wall -Wextra -O2 -g -Iinclude
LDFLAGS := -pthread

LIBDIR  := lib
SRCDIR  := src

LIBS    := $(LIBDIR)/libnet.a $(LIBDIR)/libproto.a $(LIBDIR)/libipc.a $(LIBDIR)/liblog.a

all: dirs $(LIBS) server client

dirs:
	mkdir -p $(LIBDIR)

$(SRCDIR)/net.o: $(SRCDIR)/net.c include/net.h
	$(CC) $(CFLAGS) -c $< -o $@

$(SRCDIR)/proto.o: $(SRCDIR)/proto.c include/proto.h
	$(CC) $(CFLAGS) -c $< -o $@

$(SRCDIR)/ipc.o: $(SRCDIR)/ipc.c include/ipc.h
	$(CC) $(CFLAGS) -c $< -o $@

$(SRCDIR)/log.o: $(SRCDIR)/log.c include/log.h
	$(CC) $(CFLAGS) -c $< -o $@

$(LIBDIR)/libnet.a: $(SRCDIR)/net.o
	ar rcs $@ $^

$(LIBDIR)/libproto.a: $(SRCDIR)/proto.o
	ar rcs $@ $^

$(LIBDIR)/libipc.a: $(SRCDIR)/ipc.o
	ar rcs $@ $^

$(LIBDIR)/liblog.a: $(SRCDIR)/log.o
	ar rcs $@ $^

server: $(SRCDIR)/server.o $(LIBS)
	$(CC) $(CFLAGS) $< -L$(LIBDIR) -lnet -lproto -lipc -llog -o $@ $(LDFLAGS)

client: $(SRCDIR)/client.o $(LIBS)
	$(CC) $(CFLAGS) $< -L$(LIBDIR) -lnet -lproto -lipc -llog -o $@ $(LDFLAGS)

$(SRCDIR)/server.o: $(SRCDIR)/server.c include/net.h include/proto.h include/ipc.h include/log.h
	$(CC) $(CFLAGS) -c $< -o $@

$(SRCDIR)/client.o: $(SRCDIR)/client.c include/net.h include/proto.h include/log.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(SRCDIR)/*.o
	rm -f $(LIBDIR)/*.a
	rm -f server client

.PHONY: all clean dirs
