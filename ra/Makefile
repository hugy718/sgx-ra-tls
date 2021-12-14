# Makefile to build the wolfSSL-based remote attestation TLS library.

### Intel(R) SGX SDK Settings ###
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
    SGX_COMMON_CFLAGS += -O0 -g
else
    SGX_COMMON_CFLAGS += -O2
endif

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
### Intel(R) SGX SDK Settings ###

### Project Settings ###
RATLS_LIB ?= ./
PROJECT_ROOT ?= $(shell readlink -f ..)

TSGX_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc \
						 -I$(SGX_SDK)/include/stlport
USGX_Include_Paths := -I$(SGX_SDK)/include

DEPS_Include_Paths := -I$(PROJECT_ROOT)/deps/local/include
Wolfssl_Include_Paths := -I$(DEPS_Include_Paths)/wolfssl -I$(DEPS_Include_Paths)/wolfssl/wolfcrypt/
Curl_Include_Paths := -I$(DEPS_Include_Paths)/wolfssl -I$(DEPS_Include_Paths)/wolfssl/wolfcrypt/

Compiler_Warnings := -Wall -Wextra -Wwrite-strings -Wlogical-op -Wshadow -Werror
Flags_Just_For_C := -Wno-implicit-function-declaration -std=c11

TWolfssl_C_Extra_Flags := -DSGX_SDK -DWOLFSSL_SGX -DWOLFSSL_SGX_ATTESTATION -DUSER_TIME -DWOLFSSL_CERT_EXT -DFP_MAX_BITS=8192
UWolfssl_C_Extra_Flags := -DWOLFSSL_SGX -DUSE_WOLFSSL

TCommon_C_Cpp_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector -fno-builtin-printf -I.
UCommon_C_Cpp_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes

## combine the flags ## 
override TCFLAGS += $(Compiler_Warnings) $(Flags_Just_For_C) $(TCommon_C_Cpp_Flags) $(TWolfssl_C_Extra_Flags) $(DEPS_Include_Paths) $(TSGX_Include_Paths) -I${PROJECT_ROOT} -Icommon -Iattester -Ichallenger
UCFLAGS := $(UCommon_C_Cpp_Flags) $(UWolfssl_C_Extra_Flags) $(DEPS_Include_Paths) $(USGX_Include_Paths) -I${PROJECT_ROOT} -Icommon -Iattester -Ichallenger
### Project Settings ###

### Sources ###
## trusted common lib ##
Common_t_C_Files := $(PROJECT_ROOT)/ra/common/sgx_common_t.c
Common_t_C_Objects := $(Common_t_C_Files:.c=_t.o)
$(PROJECT_ROOT)/ra/common/sgx_common_t_t.o: $(PROJECT_ROOT)/ra/common/sgx_common_t.c
	@echo $(CC) $(TCFLAGS) -c $< -o $@
	@$(CC) $(TCFLAGS) -c $< -o $@
	@echo "CC   <=  $<"
## untrusted common lib ##
Common_u_C_Files := $(PROJECT_ROOT)/ra/common/sgx_common_u.c
Common_u_C_Objects := $(Common_u_C_Files:.c=_u.o)
$(PROJECT_ROOT)/ra/common/sgx_common_u_u.o: $(PROJECT_ROOT)/ra/common/sgx_common_u.c
	@echo $(CC) $(UCFLAGS) -c $< -o $@
	@$(CC) $(UCFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

## trusted attester lib ##
Attester_t_C_Files := $(PROJECT_ROOT)/ra/attester/wolfssl-ra-attester.c \
	$(PROJECT_ROOT)/ra/attester/sgxsdk-ra-attester_t.c \
	$(PROJECT_ROOT)/ra/common/wolfssl-ra.c \
	$(PROJECT_ROOT)/option/ra_tls_options.c 

Attester_t_C_Objects := $(Attester_t_C_Files:.c=_t.o)

$(PROJECT_ROOT)/ra/attester/wolfssl-ra-attester_t.o: $(PROJECT_ROOT)/ra/attester/wolfssl-ra-attester.c
	@echo $(CC) $(TCFLAGS) -c $< -o $@
	@$(CC) $(TCFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

$(PROJECT_ROOT)/ra/attester/sgxsdk-ra-attester_t_t.o: $(PROJECT_ROOT)/ra/attester/sgxsdk-ra-attester_t.c
	@echo $(CC) $(TCFLAGS) -c $< -o $@
	@$(CC) $(TCFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

$(PROJECT_ROOT)/ra/common/wolfssl-ra_t.o: $(PROJECT_ROOT)/ra/common/wolfssl-ra.c
	@echo $(CC) $(TCFLAGS) -c $< -o $@
	@$(CC) $(TCFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

$(PROJECT_ROOT)/option/ra_tls_options_t.o: $(PROJECT_ROOT)/option/ra_tls_options.c
	@echo $(CC) $(TCFLAGS) -c $< -o $@
	@$(CC) $(TCFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

## untrusted attester lib ##
Attester_u_C_Files :=	$(PROJECT_ROOT)/ra/attester/sgxsdk-ra-attester_u.c \
	$(PROJECT_ROOT)/ra/attester/ias-ra.c \
	$(PROJECT_ROOT)/ra/attester/curl_helper.c \
	$(PROJECT_ROOT)/ra/common/wolfssl-ra.c

Attester_u_C_Objects := $(Attester_u_C_Files:.c=_u.o)
$(PROJECT_ROOT)/ra/attester/sgxsdk-ra-attester_u_u.o: $(PROJECT_ROOT)/ra/attester/sgxsdk-ra-attester_u.c
	@echo $(CC) $(UCFLAGS) -c $< -o $@
	@$(CC) $(UCFLAGS) -c $< -o $@
	@echo "CC   <=  $<"
$(PROJECT_ROOT)/ra/attester/ias-ra_u.o: $(PROJECT_ROOT)/ra/attester/ias-ra.c
	@echo $(CC) $(UCFLAGS) -c $< -o $@
	@$(CC) $(UCFLAGS) -c $< -o $@
	@echo "CC   <=  $<"
$(PROJECT_ROOT)/ra/attester/curl_helper_u.o: $(PROJECT_ROOT)/ra/attester/curl_helper.c
	@echo $(CC) $(UCFLAGS) -c $< -o $@
	@$(CC) $(UCFLAGS) -c $< -o $@
	@echo "CC   <=  $<"
$(PROJECT_ROOT)/ra/common/wolfssl-ra_u.o: $(PROJECT_ROOT)/ra/common/wolfssl-ra.c
	@echo $(CC) $(UCFLAGS) -c $< -o $@
	@$(CC) $(UCFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

## trusted challenger lib (a subset of challenger lib) ##

## challenger lib ##
Challenger_C_Files := $(PROJECT_ROOT)/ra/challenger/wolfssl-ra-challenger.c \
	$(PROJECT_ROOT)/ra/challenger/ra-challenger.c \
	$(PROJECT_ROOT)/ra/challenger/ias_sign_ca_cert.c \
	$(PROJECT_ROOT)/ra/common/wolfssl-ra.c

Challenger_C_Objects := $(Challenger_C_Files:.c=.o)
$(PROJECT_ROOT)/ra/challenger/wolfssl-ra-challenger.o: $(PROJECT_ROOT)/ra/challenger/wolfssl-ra-challenger.c
	@echo $(CC) $(UCFLAGS) -c $< -o $@
	@$(CC) $(UCFLAGS) -c $< -o $@
	@echo "CC   <=  $<"
$(PROJECT_ROOT)/ra/challenger/ra-challenger.o: $(PROJECT_ROOT)/ra/challenger/ra-challenger.c
	@echo $(CC) $(UCFLAGS) -c $< -o $@
	@$(CC) $(UCFLAGS) -c $< -o $@
	@echo "CC   <=  $<"
$(PROJECT_ROOT)/ra/challenger/ias_sign_ca_cert.o: $(PROJECT_ROOT)/ra/challenger/ias_sign_ca_cert.c
	@echo $(CC) $(UCFLAGS) -c $< -o $@
	@$(CC) $(UCFLAGS) -c $< -o $@
	@echo "CC   <=  $<"
$(PROJECT_ROOT)/ra/common/wolfssl-ra.o: $(PROJECT_ROOT)/ra/common/wolfssl-ra.c
	@echo $(CC) $(UCFLAGS) -c $< -o $@
	@$(CC) $(UCFLAGS) -c $< -o $@
	@echo "CC   <=  $<"
### Sources ###

.PHONY: all clean mrproper

all: libratls_attester_t.a libratls_attester_u.a libratls_challenger.a libratls_common_t.a libratls_common_u.a

### Edger8r related sources ###
attester/attester_t.c attester/attester_t.h attester/attester_u.c attester/attester_u.h : attester/attester.edl
	$(SGX_EDGER8R) $^ --search-path $(SGX_SDK)/include \
		--untrusted-dir attester/ --trusted-dir attester/

attester/attester_u.o: attester/attester_u.c
	@echo $(CC) $(UCFLAGS) -c $< -o $@
	@$(CC) $(UCFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

attester/attester_t.o: attester/attester_t.c
	@echo $(CC) $(TCFLAGS) -c $< -o $@
	@$(CC) $(TCFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

common/common_t.c common/common_t.h common/common_u.c common/common_u.h: common/common.edl
	@echo $(SGX_EDGER8R) $^ --search-path $(SGX_SDK)/include\
		--untrusted-dir common/ --trusted-dir common/
	$(SGX_EDGER8R) $^ --search-path $(SGX_SDK)/include\
		--untrusted-dir common/ --trusted-dir common/

common/common_u.o: common/common_u.c
	@echo $(CC) $(UCFLAGS) -c $< -o $@
	@$(CC) $(UCFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

common/common_t.o: common/common_t.c
	@echo $(CC) $(TCFLAGS) -c $< -o $@
	@$(CC) $(TCFLAGS) -c $< -o $@
	@echo "CC   <=  $<"
### Edger8r related sources ###

### Main targets ###
libratls_attester_u.a: attester/attester_u.o $(Attester_u_C_Objects)
	ar rcs $@ $(Attester_u_C_Objects)
	@echo "LINK =>  $@"


libratls_attester_t.a: attester/attester_t.o $(Attester_t_C_Objects)
	ar rcs $@ $(Attester_t_C_Objects)
	@echo "LINK =>  $@"

libratls_challenger.a : $(Challenger_C_Objects)
	ar rcs $@ $(Challenger_C_Objects)
	@echo "LINK =>  $@"

libratls_common_u.a: common/common_u.o $(Common_u_C_Objects)
	ar rcs $@ $(Common_u_C_Objects)
	@echo "LINK => $@"

libratls_common_t.a: common/common_t.o $(Common_t_C_Objects)
	ar rcs $@ $(Common_t_C_Objects)
	@echo "LINK => $@" 
### Main targets ###

### Clean commands ###
clean:
	$(RM) *.a
	$(RM) attester/*.o
	$(RM) challenger/*.o
	$(RM) common/*.o

mrproper: clean
	@rm -f attester/attester_t.c attester/attester_t.h attester/attester_u.c attester/attester_u.h 
	@rm -f common/common_t.c common/common_t.h common/common_u.c common/common_u.h
### Clean commands ###
