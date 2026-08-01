CC      := gcc
CFLAGS  := -O0 -g -fno-pic -no-pie
LDFLAGS_NORELRO := -Wl,-z,norelro
LDFLAGS_PARTIAL := -Wl,-z,relro
LDFLAGS_FULL    := -Wl,-z,relro -Wl,-z,now

all: target_norelro target_partial target_full target_smc

target_smc: target_smc.c
	$(CC) $(CFLAGS) $(LDFLAGS_PARTIAL) -o $@ $<

target_pre: target_pre.c
	$(CC) $(CFLAGS) $(LDFLAGS_PARTIAL) -o $@ $<

target_in: target_in.c
	$(CC) $(CFLAGS) $(LDFLAGS_PARTIAL) -o $@ $<

target_probe: target_probe.c
	$(CC) $(CFLAGS) $(LDFLAGS_FULL) -o $@ $<

target_demo: target_demo.c
	$(CC) $(CFLAGS) $(LDFLAGS_PARTIAL) -o $@ $<

target_probe_demo: target_probe_demo.c
	$(CC) $(CFLAGS) $(LDFLAGS_FULL) -o $@ $<

target_tls: target_tls.c
	$(CC) $(CFLAGS) $(LDFLAGS_FULL) -o $@ $<

target_tls_auth: target_tls_auth.c
	$(CC) $(CFLAGS) $(LDFLAGS_FULL) -o $@ $<

target_throw: target_throw.cpp
	g++ -O0 -g -fno-pic -no-pie -Wl,-z,relro -o $@ $<

target_norelro: target.c
	$(CC) $(CFLAGS) $(LDFLAGS_NORELRO) -o $@ $<

target_partial: target.c
	$(CC) $(CFLAGS) $(LDFLAGS_PARTIAL) -o $@ $<

target_full: target.c
	$(CC) $(CFLAGS) $(LDFLAGS_FULL) -o $@ $<

clean:
	rm -f target_norelro target_partial target_full
	rm -rf variants traces results RESULTS.md

.PHONY: all clean
