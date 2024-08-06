FROM docker.io/library/golang:1.22.5 as builder
RUN mkdir /tmp/cisin-src
COPY . /tmp/cisin-src
WORKDIR /tmp/cisin-src
RUN go build -o /tmp/cisin . gitlab.fhnw.ch/cloud/mse-cloud/cisin

FROM docker.io/library/ubuntu:24.04
RUN apt-get update && apt install -y curl &&  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin && apt remove -y curl && apt clean
COPY --from=builder /tmp/cisin /opt/cisin
USER root
ENTRYPOINT ["/opt/cisin"]
