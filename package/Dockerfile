FROM docker.io/library/ubuntu:23.10
RUN apt-get update && apt install -y curl &&  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin && apt remove -y curl && apt clean
COPY out/cisin /opt/cisin
USER root
CMD /opt/cisin
