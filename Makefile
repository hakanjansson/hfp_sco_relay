CFLAGS = -O0 -g -Wall -Werror $(shell pkg-config --cflags --libs gio-unix-2.0) -lbluetooth -lm

hfp_sco_relay: hfp_sco_relay.c log.c
	gcc hfp_sco_relay.c log.c -o hfp_sco_relay $(CFLAGS)

clean:
	rm -f hfp_sco_relay

.PHONY: clean