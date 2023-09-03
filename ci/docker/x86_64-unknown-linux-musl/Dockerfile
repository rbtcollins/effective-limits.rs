FROM ubuntu:20.04@sha256:33a5cc25d22c45900796a1aca487ad7a7cb09f09ea00b779e3b2026b4fc2faba

COPY ci/docker/scripts/sccache.bash /scripts/

RUN \
  apt-get update && \
  apt-get install -qy \
    musl-dev \
    musl-tools \
    curl \
    ca-certificates \
    perl \
    make \
    gcc && \
  bash /scripts/sccache.bash
