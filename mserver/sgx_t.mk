### Intel(R) SGX SDK Settings ###
SGX_MODE ?= HW
SGX_DEBUG ?= 0
SGX_PRERELEASE ?= 1
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
        SGX_COMMON_CFLAGS += -O0 -g -DSGX_DEBUG
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

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif

DCAP_TVL_LIB = sgx_dcap_tvl
### Intel(R) SGX SDK Settings ###

### Project Settings ###
SGX_RA_TLS_INSTALL_DIR ?= $(abspath ../install)
SGX_RA_TLS_Include_Path := $(SGX_RA_TLS_INSTALL_DIR)/include
SGX_RA_TLS_Lib_Path := $(SGX_RA_TLS_INSTALL_DIR)/lib

SGX_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc

Flags_Just_For_C := -Wno-implicit-function-declaration -std=c11
Common_C_Cpp_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector -fno-builtin -fno-builtin-printf -I. \
										-Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls \
										-Wjump-misses-init -Wstrict-prototypes \
										-Wunsuffixed-float-constants
Wolfssl_C_Extra_Flags := -DSGX_SDK -DWOLFSSL_SGX
Wolfssl_C_Extra_Flags += -DUSER_TIME -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_KEY_GEN -DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT -DFP_MAX_BITS=8192

Server_Enclave_C_Flags := $(Flags_Just_For_C) $(Common_C_Cpp_Flags) $(Wolfssl_C_Extra_Flags) -Itrusted $(SGX_Include_Paths) -I$(SGX_RA_TLS_Include_Path)

Crypto_Library_Name := sgx_tcrypto

Server_Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) \
	-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-L$(SGX_RA_TLS_Lib_Path) -lratls_ext -lratls_attester_t -lratls_challenger_t -lratls_common_t -lwolfssl.sgx.static.lib \
	-Wl,--whole-archive -l$(DCAP_TVL_LIB) -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=trusted/Server_Enclave.lds
### Project Settings ###

### Phony targets ###
.PHONY: all clean

### Build all ###
ifeq ($(Build_Mode), HW_RELEASE)
all: Server_Enclave.so
	@echo "Build enclave Server_Enclave.so [$(Build_Mode)|$(SGX_ARCH)] success!"
	@echo
	@echo "*********************************************************************************************************************************************************"
	@echo "PLEASE NOTE: In this mode, please sign the Server_Enclave.so first using Two Step Sign mechanism before you run the app to launch and access the enclave."
	@echo "*********************************************************************************************************************************************************"
	@echo
else
all: Server_Enclave.signed.so
endif

### Sources ###
### Edger8r related sourcs ###
trusted/Server_Enclave_t.c: $(SGX_EDGER8R) ./trusted/Server_Enclave.edl
	cd ./trusted && $(SGX_EDGER8R) --trusted ../trusted/Server_Enclave.edl --search-path ../trusted --search-path $(SGX_SDK)/include --search-path $(SGX_RA_TLS_Include_Path)
	@echo "GEN  =>  $@"

trusted/Server_Enclave_t.o: ./trusted/Server_Enclave_t.c
	$(CC) $(Server_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"
### Edger8r related sourcs ###

### Enclave Image ###
Server_Enclave.so: trusted/Server_Enclave_t.o
	$(CXX) $^ -o $@ $(Server_Enclave_Link_Flags)
	@echo "LINK =>  $@"

### Signing ###
Server_Enclave.signed.so: Server_Enclave.so
	$(SGX_ENCLAVE_SIGNER) sign -key trusted/Server_Enclave_private.pem -enclave Server_Enclave.so -out $@ -config trusted/Server_Enclave.config.xml
	@echo "SIGN =>  $@"
### Sources ###

### Clean command ###
clean:
	rm -f Server_Enclave.* trusted/Server_Enclave_t.*
