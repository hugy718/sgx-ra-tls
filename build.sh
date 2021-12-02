#!/bin/bash
set -x

function usage() {
    echo "./build.sh"
}

# You need the SGX SDK and PSW installed.
if [[ $# -gt 0 ]]; then
    echo "wrong number of arguments"
    usage
    exit 1
fi

export CC=gcc

# create options file to use EPID IAS. 
make option/ra_tls_options.c

# build dependencies: wolfssl and curl
mkdir -p deps
make -j`nproc` deps

# build clients and servers
echo "Building clients and servers..."
make clients || exit 1
make server || exit 1