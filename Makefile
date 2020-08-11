CFLAGS = -O0 -g -Wall -Werror $(shell pkg-config --cflags --libs gio-unix-2.0) -lbluetooth

all: hfp_sco_relay log_server

hfp_sco_relay: hfp_sco_relay.c log.c hfp_sco_relay.h
	gcc hfp_sco_relay.c log.c -o hfp_sco_relay $(CFLAGS)

log_server: log_server.c hfp_sco_relay.h
	gcc log_server.c -o log_server $(CFLAGS)

clean:
	rm -f hfp_sco_relay log_server

.PHONY: clean