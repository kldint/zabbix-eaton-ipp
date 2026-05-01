CC      = gcc
CFLAGS  = -Wall -O2
LDFLAGS = -lcurl -lssl -lcrypto -lcjson

build: check_eaton_ipp.c
	$(CC) $(CFLAGS) -o check_eaton_ipp check_eaton_ipp.c $(LDFLAGS)

clean:
	rm -f check_eaton_ipp
