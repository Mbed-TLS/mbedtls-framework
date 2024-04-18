CFLAGS ?= -Wall -Werror -std=c99 -D_XOPEN_SOURCE=1 -D_POSIX_C_SOURCE=200809L

ifeq ($(DEBUG),1)
	CFLAGS += -DDEBUG -O0 -g
endif

.PHONY: all lib test run docker ci

all: lib test

lib:
	$(MAKE) -C src CFLAGS="$(CFLAGS)"

test: lib
	$(MAKE) -C test CFLAGS="$(CFLAGS)"

clean:
	rm -f $(PSA_LIB) $(PSA_LIB_OBJS)
	$(MAKE) -C test clean
	$(MAKE) -C src clean

run: test
	pkill psa_partition || true
	pkill psa_client || true
	ipcs | grep q | awk '{ printf " -q " $$2 }' | xargs ipcrm > /dev/null 2>&1 || true
	(sleep 1 && ./test/psa_client)&
	./test/psa_partition
