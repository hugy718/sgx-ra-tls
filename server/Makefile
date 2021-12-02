SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64

all:
ifndef DEPS_INCLUDE_DIR
	$(error DEPS_INCLUDE_DIR is not set. Please set to ratls dependency headers directory)
endif
ifndef SGX_WOLFSSL_LIB
	$(error SGX_WOLFSSL_LIB is not set. Please set to wolfssl library (build for RA_TLS) directory)
endif
	$(MAKE) -ef sgx_u.mk all
	$(MAKE) -ef sgx_t.mk all

clean:
	$(MAKE) -ef sgx_u.mk clean
	$(MAKE) -ef sgx_t.mk clean

