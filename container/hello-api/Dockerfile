# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

######## full image ########

FROM public.ecr.aws/amazonlinux/amazonlinux:2 as full_image

RUN amazon-linux-extras install aws-nitro-enclaves-cli && \
    yum install aws-nitro-enclaves-cli-devel jq -y

WORKDIR /ne-deps

# Copy only the required binaries to /ne-deps folder.
#
RUN BINS="\
    /usr/bin/nitro-cli \
    /usr/bin/nitro-enclaves-allocator \
    /usr/bin/vsock-proxy \
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
    cp -f /etc/nitro_enclaves/vsock-proxy.yaml /ne-deps/etc/nitro_enclaves && \
    cp -f /etc/nitro_enclaves/allocator.yaml /ne-deps/etc/nitro_enclaves/allocator.yaml

######## hello image ########

FROM public.ecr.aws/amazonlinux/amazonlinux:2 as image

# Copying dependencies of the enclave apps from the 'full_image'
# to shrink the final image size.
#
RUN yum install python3 -y
COPY --from=full_image /ne-deps/etc /etc
COPY --from=full_image /ne-deps/lib64 /lib64
COPY --from=full_image /ne-deps/run /run
COPY --from=full_image /ne-deps/usr /usr
COPY --from=full_image /ne-deps/var /var

COPY bin/hello-api.eif /home/hello-api.eif
COPY hello-api/run.sh /home/run.sh
COPY hello-api/proxy-config.json /home/proxy-config.json
COPY hello-api/vsock.py /home/vsock.py
RUN chmod +x /home/run.sh
CMD ["/home/run.sh"]
