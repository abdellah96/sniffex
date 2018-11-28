CC         = cc
LD         = $(CC)
CPPFLAGS   = -D_DEFAULT_SOURCE
CFLAGS     = -c -O0 -g -std=c99  $(CPPFLAGS)
LDFLAGS    = -lpcap

BIN = sniffex
OBJ = verbosity.o live_scan.o offline_scan.o decode_smtp.o decode_eth.o decode_ip.o decode_http.o decode_ftp.o decode_bootp.o decode_tcp.o decode_udp.o decode_arp.o decode_dns.o  main.o

all: $(BIN)

$(BIN): $(OBJ)
	@$(LD) -o $@ $^ $(LDFLAGS)

.c.o:
	@$(CC) -o $@ $< $(CFLAGS)

clean:
	rm -f $(BIN) *.o
