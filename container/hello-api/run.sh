#!/bin/bash -e

readonly EIF_PATH="/home/hello-api.eif"
readonly ENCLAVE_CPU_COUNT=2
readonly ENCLAVE_MEMORY_SIZE=6144

main() {
    if [ -z "$AWS_REGION" ]; then
        echo "AWS_REGION must be set" >&2
        exit 1
    fi

    nitro-cli run-enclave --cpu-count $ENCLAVE_CPU_COUNT --memory $ENCLAVE_MEMORY_SIZE \
        --eif-path $EIF_PATH --debug-mode 2>&1 > /dev/null

    vsock-proxy 8080 &

    sleep infinity
}

main