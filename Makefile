CFLAGS = -O0 -g -Wall -Werror $(shell pkg-config --cflags --libs gio-unix-2.0) -lbluetooth

all: hfp_sco_relay log_server test_relay

hfp_sco_relay: hfp_sco_relay.c log.c hfp_sco_relay.h
	gcc $< log.c -o $@ $(CFLAGS)

log_server: log_server.c hfp_sco_relay.h
	gcc $< -o $@ $(CFLAGS)

test_relay: test_relay.c
	gcc $< -o $@ $(CFLAGS)

clean:
	rm -f hfp_sco_relay log_server

.PHONY: clean