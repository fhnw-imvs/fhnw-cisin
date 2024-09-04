FROM docker.io/library/golang:1.22.5 AS builder
RUN mkdir /tmp/cisin-src
COPY . /tmp/cisin-src
WORKDIR /tmp/cisin-src
RUN go build -o /tmp/cisin . gitlab.fhnw.ch/cloud/mse-cloud/cisin
RUN GOPATH=/tmp/go go install github.com/google/go-containerregistry/cmd/crane@latest

FROM docker.io/library/ubuntu:24.04
COPY --from=builder /tmp/go/bin/crane /opt/crane
RUN apt-get update &&\
    apt install -y curl jq &&\
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin &&\
    apt clean
COPY --from=builder /tmp/cisin /opt/cisin
USER root
ENTRYPOINT ["/opt/cisin"]
