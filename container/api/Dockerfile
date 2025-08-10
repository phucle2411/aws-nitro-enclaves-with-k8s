# Build the API enclave application
FROM public.ecr.aws/amazonlinux/amazonlinux:2 as full_image

RUN amazon-linux-extras install aws-nitro-enclaves-cli && \
    yum install aws-nitro-enclaves-cli-devel jq -y

WORKDIR /ne-deps

# Copy only the required binaries to /ne-deps folder.
#
RUN BINS="\
    /usr/bin/nitro-cli \
    /usr/bin/nitro-enclaves-allocator \
    /usr/bin/jq \
    " && \
    for bin in $BINS; do \
        { echo "$bin"; ldd "$bin" | grep -Eo "/.*lib.*/[^ ]+"; } | \
            while read path; do \
                mkdir -p ".$(dirname $path)"; \
                cp -fL "$path" ".$path"; \
            done \
    done

# Prepare other required files and folders for the final image.
#
RUN \
    mkdir -p /ne-deps/etc/nitro_enclaves && \
    mkdir -p /ne-deps/run/nitro_enclaves && \
    mkdir -p /ne-deps/var/log/nitro_enclaves && \
    cp -rf /usr/share/nitro_enclaves/ /ne-deps/usr/share/ && \
    cp -f /etc/nitro_enclaves/allocator.yaml /ne-deps/etc/nitro_enclaves/allocator.yaml

FROM public.ecr.aws/amazonlinux/amazonlinux:2
RUN amazon-linux-extras install aws-nitro-enclaves-cli && \
    yum install aws-nitro-enclaves-cli-devel jq -y

COPY --from=build /app/api /usr/bin/api
COPY bin/api.eif /home/api.eif
COPY api/run.sh /home/run.sh

CMD ["/home/run.sh"]