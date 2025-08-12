#!/bin/bash -e

readonly EIF_PATH="/home/hello-api.eif"
readonly ENCLAVE_CPU_COUNT=2
readonly ENCLAVE_MEMORY_SIZE=1024

main() {
    if [ -z "$AWS_REGION" ]; then
        echo "AWS_REGION must be set" >&2
        exit 1
    fi

    nitro-cli run-enclave --cpu-count $ENCLAVE_CPU_COUNT --memory $ENCLAVE_MEMORY_SIZE \
        --eif-path $EIF_PATH --debug-mode
        
    local enclave_id=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
    echo "-------------------------------"
    echo "Enclave ID is $enclave_id"
    echo "-------------------------------"

    nitro-cli console --enclave-id $enclave_id # blocking call.
}

main