CC      := gcc
CFLAGS  := -Wall -Wextra -O2 -g -Iinclude
LDFLAGS := -pthread

LIBDIR  := lib
SRCDIR  := src

LIBS    := $(LIBDIR)/libnet.a \
           $(LIBDIR)/libproto.a \
           $(LIBDIR)/libipc.a \
           $(LIBDIR)/liblog.a \
           $(LIBDIR)/libtls.a

all: dirs $(LIBS) server client

dirs:
	 mkdir -p $(LIBDIR)

# ---- libnet.a ----
$(LIBDIR)/libnet.a: $(SRCDIR)/net.o
	 ar rcs $@ $^

$(SRCDIR)/net.o: $(SRCDIR)/net.c include/net.h
	 $(CC) $(CFLAGS) -c $< -o $@

# ---- libproto.a ----
$(LIBDIR)/libproto.a: $(SRCDIR)/proto.o
	 ar rcs $@ $^

$(SRCDIR)/proto.o: $(SRCDIR)/proto.c include/proto.h
	 $(CC) $(CFLAGS) -c $< -o $@

# ---- libipc.a ----
$(LIBDIR)/libipc.a: $(SRCDIR)/ipc.o
	 ar rcs $@ $^

$(SRCDIR)/ipc.o: $(SRCDIR)/ipc.c include/ipc.h
	 $(CC) $(CFLAGS) -c $< -o $@

# ---- liblog.a ----
$(LIBDIR)/liblog.a: $(SRCDIR)/log.o
	 ar rcs $@ $^

$(SRCDIR)/log.o: $(SRCDIR)/log.c include/log.h
	 $(CC) $(CFLAGS) -c $< -o $@

# ---- libtls.a (Newly added TLS library) ----
$(LIBDIR)/libtls.a: $(SRCDIR)/tls.o
	 ar rcs $@ $^

$(SRCDIR)/tls.o: $(SRCDIR)/tls.c include/tls.h
	 $(CC) $(CFLAGS) -c $< -o $@

# ---- server / client ----

server: $(SRCDIR)/server.o $(LIBS)
	 $(CC) $(CFLAGS) $< -L$(LIBDIR) -lnet -lproto -lipc -llog -ltls -lssl -lcrypto $(LDFLAGS) -o $@

$(SRCDIR)/server.o: $(SRCDIR)/server.c \
                    include/net.h include/proto.h include/ipc.h \
                    include/log.h include/tls.h
	 $(CC) $(CFLAGS) -c $< -o $@

client: $(SRCDIR)/client.o $(LIBS)
	 $(CC) $(CFLAGS) $< -L$(LIBDIR) -lnet -lproto -llog -ltls -lssl -lcrypto $(LDFLAGS) -o $@

$(SRCDIR)/client.o: $(SRCDIR)/client.c \
                    include/net.h include/proto.h include/log.h \
                    include/tls.h
	 $(CC) $(CFLAGS) -c $< -o $@

clean:
	 rm -f $(SRCDIR)/*.o
	 rm -f $(LIBDIR)/*.a
	 rm -f server client

.PHONY: all clean dirs
