CPPFLAGS=
CFLAGS=-O0 -g -Wall
#CFLAGS=-O2

LIBS=-ljack -lpcap
OBJ=packetpunk.o

all: packetpunk

$(OBJ): %.o: %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

packetpunk: $(OBJ)
	$(CC) -o packetpunk $(OBJ) $(LIBS)

.PHONY: clean
clean:
	rm -f packetpunk *.o
