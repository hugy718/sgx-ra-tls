# Makefile to build the wolfSSL-based remote attestation TLS library.
### Project Settings ###
PROJECT_ROOT ?= $(shell readlink -f ..)

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

TSGX_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc
USGX_Include_Paths := -I$(SGX_SDK)/include

Common_C_Cpp_Warnings := -Wall -Wextra -Wchar-subscripts \
	-Wno-coverage-mismatch \
	-Winit-self -Wpointer-arith -Wreturn-type \
	-Waddress -Wsequence-point -Wformat-security \
	-Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
	-Wcast-align -Wcast-qual -Wconversion -Wredundant-decls
Common_C_Cpp_Warnings += -Wwrite-strings -Wlogical-op

Common_C_Warnings := -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants

TCommon_C_Cpp_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector -fno-builtin-printf
UCommon_C_Cpp_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes

TCommon_C_Flags := $(Common_C_Cpp_Warnings) $(Common_C_Warnings) $(TCommon_C_Cpp_Flags) -Wno-implicit-function-declaration -std=c11
UCommon_C_Flags := $(Common_C_Cpp_Warnings) $(Common_C_Warnings) $(UCommon_C_Cpp_Flags)
### Intel(R) SGX SDK Settings ###

### Project Settings ###
DEPS_Include_Paths := -I$(PROJECT_ROOT)/deps/local/include
RATLS_Include_Paths := -I./include

TWolfssl_C_Extra_Flags := -DSGX_SDK -DWOLFSSL_SGX -DWOLFSSL_SGX_ATTESTATION -DUSER_TIME -DWOLFSSL_CERT_EXT -DFP_MAX_BITS=8192
UWolfssl_C_Extra_Flags := -DWOLFSSL_SGX -DUSE_WOLFSSL

TCommon_C_Flags += $(TWolfssl_C_Extra_Flags) $(TSGX_Include_Paths) $(DEPS_Include_Paths) $(RATLS_Include_Paths)

UCommon_C_Flags += $(UWolfssl_C_Extra_Flags) $(USGX_Include_Paths) $(DEPS_Include_Paths) $(RATLS_Include_Paths)
### Project Settings ###

### Sources ###

.SECONDEXPANSION:

## trusted common lib ##
Common_t_C_Files := common/internal_util_wolfssl.c common/wolfssl_tpatch.c
Common_t_C_Objects := $(Common_t_C_Files:%.c=%_t.o)
$(Common_t_C_Objects) : $$(patsubst %_t.o,%.c, $$@)
	$(CC) $(TCommon_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

## untrusted common lib ##
Common_u_C_Files := common/internal_util_wolfssl.c common/wolfssl_upatch.c
Common_u_C_Objects := $(Common_u_C_Files:%.c=%_u.o)
$(Common_u_C_Objects) : $$(patsubst %_u.o,%.c, $$@)
	$(CC) $(UCommon_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

## trusted attester lib ##
Attester_t_C_Files := attester/tattester_wolfssl.c \
	attester/tattester.c \
	$(PROJECT_ROOT)/option/ra_tls_options.c 

Attester_t_C_Objects := $(Attester_t_C_Files:%.c=%_t.o)

$(Attester_t_C_Objects) : $$(patsubst %_t.o,%.c, $$@)
	$(CC) $(TCommon_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

## untrusted attester lib ##

Attester_u_C_Files :=	attester/uattester_wolfssl.c \
	attester/uattester.c \
	attester/curl_helper.c

Attester_u_C_Objects := $(Attester_u_C_Files:%.c=%_u.o)

$(Attester_u_C_Objects) : $$(patsubst %_u.o,%.c, $$@)
	$(CC) $(UCommon_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

## trusted challenger lib ## 
## (additionally needs the ecall implementation of set verify) ##
Challenger_t_C_Files := challenger/challenger_wolfssl.c \
	challenger/challenger.c \
	challenger/ias_sign_ca_cert.c

Challenger_t_C_Objects := $(Challenger_t_C_Files:%.c=%_t.o)
$(Challenger_t_C_Objects) : $$(patsubst %_t.o,%.c, $$@)
	$(CC) $(TCommon_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

## challenger lib ##
Challenger_C_Files := challenger/challenger_wolfssl.c \
	challenger/uchallenger.c \
	challenger/challenger.c \
	challenger/ias_sign_ca_cert.c

Challenger_C_Objects := $(Challenger_C_Files:.c=_u.o)
$(Challenger_C_Objects) : $$(patsubst %_u.o,%.c, $$@)
	$(CC) $(UCommon_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"
### Sources ###

.PHONY: all clean mrproper

all: libratls_attester_t.a libratls_attester_u.a libratls_challenger_t.a libratls_challenger.a libratls_common_t.a libratls_common_u.a libratls_ext.a

### Main targets ###
libratls_attester_u.a: $(Attester_u_C_Objects)
	ar rcs $@ $^
	@echo "LINK =>  $@"

libratls_attester_t.a: $(Attester_t_C_Objects)
	ar rcs $@ $^
	@echo "LINK =>  $@"

libratls_challenger_t.a: $(Challenger_t_C_Objects)
	ar rcs $@ $^
	@echo "LINK =>  $@"

libratls_challenger.a : $(Challenger_C_Objects)
	ar rcs $@ $^
	@echo "LINK =>  $@"

server/ecall_patch.o : server/ecall_patch.c
	$(CC) $(TCommon_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

libratls_ext.a : server/ecall_patch.o
	ar rcs $@ $^
	@echo "LINK =>  $@"

libratls_common_u.a: $(Common_u_C_Objects)
	ar rcs $@ $(Common_u_C_Objects)
	@echo "LINK => $@"

libratls_common_t.a: $(Common_t_C_Objects)
	ar rcs $@ $(Common_t_C_Objects)
	@echo "LINK => $@" 
### Main targets ###

### Clean commands ###
clean:
	$(RM) *.a
	$(RM) attester/*.o
	$(RM) challenger/*.o
	$(RM) common/*.o
	$(RM) server/*.o

mrproper: clean
### Clean commands ###
