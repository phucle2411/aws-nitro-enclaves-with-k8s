# Build the API enclave application
FROM public.ecr.aws/amazonlinux/amazonlinux:2 AS build
RUN yum install -y golang git
WORKDIR /app
COPY go.mod .
COPY main.go .
RUN go build -o api