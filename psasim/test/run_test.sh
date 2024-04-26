#!/bin/bash

set -e

function clean_run() {
    pkill psa_partition || true
    pkill psa_client || true
    ipcs | grep q | awk '{ printf " -q " $$2 }' | xargs ipcrm > /dev/null 2>&1 || true
}

clean_run

./psa_partition &
SERV_PID=$!
./psa_client
wait $SERV_PID
