# syntax=docker/dockerfile:1
#
# Recorder and Core chain harness image.
#
# Base: python:3.12-slim, pinned by digest (multi-arch index).
# Bitcoin Core: the official v32.1 Linux release tarball, supplied through the
# named build context "release" and checked against the SHA256 values published
# in the v32.1 SHA256SUMS file (whose builder signatures were verified on the host).
#
# Build (see Makefile):
#   docker build --build-context release=<dir with the tarball> -t bcs-recorder:32.1 conformance/recorder

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ARG TARGETARCH
ARG CORE_VERSION=32.1
ARG CORE_SHA256_ARM64=7ed37c7373eb6aa3e3f72842596a1afeba1b223717033cade9842b25773e1922
ARG CORE_SHA256_AMD64=61545c17c3120fb7412f896d248b11993af04ec8817aad3649c55b2afb044963

COPY --from=release bitcoin-${CORE_VERSION}-*-linux-gnu.tar.gz /tmp/core/

RUN set -eu; \
    case "${TARGETARCH}" in \
      arm64) f="bitcoin-${CORE_VERSION}-aarch64-linux-gnu.tar.gz"; s="${CORE_SHA256_ARM64}" ;; \
      amd64) f="bitcoin-${CORE_VERSION}-x86_64-linux-gnu.tar.gz"; s="${CORE_SHA256_AMD64}" ;; \
      *) echo "unsupported architecture ${TARGETARCH}"; exit 1 ;; \
    esac; \
    echo "${s}  /tmp/core/${f}" | sha256sum -c -; \
    tar -xzf "/tmp/core/${f}" -C /opt; \
    rm -rf /tmp/core; \
    echo "${s}" > /opt/bitcoin-${CORE_VERSION}/TARBALL_SHA256; \
    echo "${f}" > /opt/bitcoin-${CORE_VERSION}/TARBALL_NAME; \
    /opt/bitcoin-${CORE_VERSION}/bin/bitcoind -version | head -1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BCS_CORE_DIR=/opt/bitcoin-32.1 \
    BCS_CORE_SRC=/core \
    PATH=/opt/bitcoin-32.1/bin:$PATH

COPY config.ini /opt/bcs/config.ini
COPY pins.json *.py /opt/bcs/recorder/
COPY extra/ /opt/bcs/recorder/extra/
WORKDIR /opt/bcs/recorder
