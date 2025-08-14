#!/bin/bash -e

readonly EIF_PATH="/home/hello-api.eif"
readonly ENCLAVE_CPU_COUNT=2
readonly ENCLAVE_MEMORY_SIZE=1024
readonly PROXY_SCRIPT="/home/vsock.py"

main() {
    if [ -z "$AWS_REGION" ]; then
        echo "AWS_REGION must be set" >&2
        exit 1
    fi
    vsock-proxy 8000 kms.ap-southeast-1.amazonaws.com 443 &

    nitro-cli run-enclave --cpu-count $ENCLAVE_CPU_COUNT --memory $ENCLAVE_MEMORY_SIZE \
        --eif-path $EIF_PATH --debug-mode
    sleep 5
    local enclave_id=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
    echo "-------------------------------"
    echo "Enclave ID is $enclave_id"
    echo "-------------------------------"

    # Start the proxy in background
    # echo "Starting VSOCK proxy..."
    # python3 $PROXY_SCRIPT both --config /home/proxy-config.json \
    #     --log-level INFO > /var/log/vsock-proxy.log 2>&1 &
    # PROXY_PID=$!
    
    # echo "Proxy started with PID: $PROXY_PID"
    # echo "Proxy logs: /var/log/vsock-proxy.log"
    # echo "-------------------------------"
    
    nitro-cli console --enclave-id $enclave_id # blocking call.
}

main