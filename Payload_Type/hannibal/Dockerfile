# Need the newer MingW
FROM python:3.11.10-bookworm

ARG CA_CERTIFICATE
ARG NPM_REGISTRY
ARG PYPI_INDEX
ARG PYPI_INDEX_URL
ARG DOCKER_REGISTRY_MIRROR
ARG HTTP_PROXY
ARG HTTPS_PROXY

RUN apt-get update && \
    apt-get install -y \
    mingw-w64 \
    mingw-w64-x86-64-dev \
    make \
    nasm \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install pycryptodome mythic-container==0.5.12 pefile

WORKDIR /Mythic/

CMD ["python3", "main.py"]