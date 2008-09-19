CFLAGS=-O0 -g -Wall

DESTDIR=
PREFIX=/usr/local

INSTALL=/usr/bin/install

LIBS=-ljack -lpcap
OBJ=packetpunk.o

all: packetpunk

$(OBJ): %.o: %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

packetpunk: $(OBJ)
	$(CC) -o packetpunk $(OBJ) $(LIBS)

install: packetpunk
	$(INSTALL) -m 755 packetpunk $(DESTDIR)$(PREFIX)/packetpunk

.PHONY: clean
clean:
	rm -f packetpunk *.o
