INCLUDE := -I../include/ -I./psa_manifest
LIB := -L../src -lpsaff

TEST_BIN = 	psa_client \
			psa_partition

.PHONY: all clean

all: $(TEST_BIN)

psa_client:
	$(CC) $(INCLUDE) $(CFLAGS) client.c $(LIB) -o $@

psa_partition: psa_ff_bootstrap_TEST_PARTITION.c
	$(CC) $(INCLUDE) $(CFLAGS) $< $(LIB) -o $@

psa_ff_bootstrap_%.c:
	../tools/psa_autogen.py manifest.json

clean:
	rm -f $(TEST_BIN) psa_ff_bootstrap_*.c
