INCLUDE := -I../include/ -I./psa_manifest
LIB := -L../src -lpsaff

TEST_BIN = 	psa_client \
			psa_partition

GENERATED_H_FILES =	./psa_manifest/manifest.h \
					./psa_manifest/pid.h \
					./psa_manifest/sid.h

.PHONY: all clean

all: $(TEST_BIN)

psa_client: $(GENERATED_H_FILES)
psa_client: client.c
	$(CC) $(INCLUDE) $(CFLAGS) client.c $(LIB) -o $@

psa_partition: $(GENERATED_H_FILES)
psa_partition: psa_ff_bootstrap_TEST_PARTITION.c server.c
	$(CC) $(INCLUDE) $(CFLAGS) $< $(LIB) -o $@

psa_ff_bootstrap_%.c psa_manifest/%.h:
	../tools/psa_autogen.py manifest.json

clean:
	rm -f $(TEST_BIN) psa_ff_bootstrap_*.c
	rm -f psa_notify_* psa_service_*
	rm -f psa_manifest/*
