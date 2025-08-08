# Build the API enclave application
FROM public.ecr.aws/amazonlinux/amazonlinux:2 AS build
RUN yum install -y golang git
WORKDIR /app
COPY go.mod .
COPY main.go .
RUN go build -o api

# Final image with Nitro CLI and vsock proxy
FROM public.ecr.aws/amazonlinux/amazonlinux:2
RUN amazon-linux-extras install aws-nitro-enclaves-cli && \
    yum install aws-nitro-enclaves-cli-devel jq -y

COPY --from=build /app/api /usr/bin/api
COPY bin/api.eif /home/api.eif
COPY run.sh /home/run.sh

CMD ["/home/run.sh"]