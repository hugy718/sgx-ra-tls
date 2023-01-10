Intel sgx-ra-tls repo but with only wolfssl epid and ecdsa.

This repo is prepared from the original sgx-ra-tls repo [link](https://github.com/cloud-security-research/sgx-ra-tls).

The intention is to have a streamlined codebase for easily prototyping systems with proper EPID/ECDSA remote attestation setup.

The old repo seems no longer being maintained. It uses outdated EPID and ECDSA APIs. This repo updates those to an more up-to-date version (working with SDK-2.14).

# Introduction

This project provides a proof-of-concept implementation on how to integrate Intel SGX remote attestation into the TLS connection setup. Conceptually, we extend the standard X.509 certificate with SGX-related information. The additional information allows the receiver of the certificate to verify that it is indeed communicating with an SGX enclave. The white paper in the  Intel's original sgx-ra-tls repository "Integrating Remote Attestation with Transport Layer Security" provides more details. RA-TLS supports [EPID](https://software.intel.com/sites/default/files/managed/57/0e/ww10-2016-sgx-provisioning-and-attestation-final.pdf).

## Repository Structure

The repository root directory contains code to generate and parse extended X.509 certificates. The build system creates the following executables:

* server: attester server.
* mserver: attester server but also challenges enclave client.
* client: challenger of enclave server.
* tclient: mutually attest with mserver.

The server and client codes are from the wolfssl-example repository patched according to the original Intel sgx-ra-tls repository. Those example codes are not updated frequently since then.

## Code Structure (need update)

The code is split into two parts: the attester and the challenger. The challenger parses certificates, computes signatures and hashsums. The attester generates keys, certificates and interfaces with SGX. The challenger and attester are implemented with the TLS libraries: wolfSSL ([challenger](wolfssl-ra-challenger.c), [attester](wolfssl-ra-attester.c)).

The attester's code consists of [trusted](sgxsdk-ra-attester_t.c) and [untrusted](sgxsdk-ra-attester_u.c) SGX-SDK specific code to produce a quote using the SGX SDK.

Given a quote, there is [code to obtain an attestation verification report](ias-ra.c) from the Intel Attestation Service. This code depends on libcurl.

[An SGX SDK-based server](deps/wolfssl-examples/SGX_Linux) based on wolfSSL demonstrates how to use the [public attester API](ra-attester.h).

We provide one non-SGX clients [wolfSSL](client/client-tls.c). They use the public [challenger's API](ra-challenger.h). There is one SGX client demonstrating mutual authentication (code: [client-tls.c](deps/wolfssl-examples/tls/client-tls.c), binary: wolfssl-client-mutual).

# Build

We have tested the code with enclaves created using the Intel SGX SDK.

## Prerequisites

The code is tested with the [Intel SGX Linux 2.14 Release](https://01.org/intel-softwareguard-extensions/downloads/intel-sgx-linux-2.4-release) installed on the host (Ubuntu 20.04). Results may vary with different versions. Follow the official instructions to install the components and ensure they are working as intended.

To use the Intel Attestation Service for EPID-based attestation an [account must be created](https://api.portal.trustedservices.intel.com/EPID-attestation). The registration process will provide a subscription key and a software provider ID (SPID). The script [ra_tls_options.c.sh](ra_tls_options.c.sh) generates a C source file with these values. Either define the environment variables before building or invoke the script manually, i.e., `SPID=... EPID_SUBSCRIPTION_KEY=... QUOTE_TYPE=... bash ra_tls_options.c.sh`. See [ra_tls_options.c.sh](ra_tls_options.c.sh) for the specific format of each variable.

For ECDSA, the SGX nodes need to be setup according to [1] [2]. Note that the DCAP library version needs to match with the SDK version. For SDK 2.14, the matching version is 2.11.

## Build Instructions

The [build script](build.sh) creates executables based on the Intel SGX SDK

```sh
./build.sh
```

For ECDSA:

```sh
USE_ECDSA=1 ./build.sh
```

# Run

launch the server with under their respective directory

```sh
./App
# for ecdsa to use out-of-proc aesm
SGX_AESM_ADDR=1 ./App 
```

run the clients

```sh
./wolfssl-client
# for mtclient
cd mtclient
SGX_AESM_ADDR=1 ./App
```

### Non-SGX clients

Execute the non-SGX binaries wolfssl-client in the project's root directory. The client outputs a bunch of connection-related information, such as the server's SGX identity (MRENCLAVE, MRSIGNER). You can cross-check this with what the server reports in its output.

## references

* [PCCS setup][1]

[1]:[https://www.intel.com/content/www/us/en/developer/articles/guide/intel-software-guard-extensions-data-center-attestation-primitives-quick-install-guide.html]

* [DCAP generation and verification tutorial][2]

[2]: https://www.intel.com/content/www/us/en/developer/articles/technical/quote-verification-attestation-with-intel-sgx-dcap.html