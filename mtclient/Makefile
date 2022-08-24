SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64

all:
	$(MAKE) -ef sgx_u.mk all
	$(MAKE) -ef sgx_t.mk all

clean:
	$(MAKE) -ef sgx_u.mk clean
	$(MAKE) -ef sgx_t.mk clean

