### Intel(R) SGX SDK Settings ###
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
### Intel(R) SGX SDK Settings ###

### Project Settings ###
SGX_RA_TLS_ATTESTER_DIR="../ra/attester"
SGX_RA_TLS_CHALLENGER_DIR="../ra/challenger"
SGX_RA_TLS_COMMON_DIR="../ra/common"
SGX_RA_TLS_Include_Paths := -I$(SGX_RA_TLS_ATTESTER_DIR) \
						 -I$(SGX_RA_TLS_CHALLENGER_DIR) \
						 -I$(SGX_RA_TLS_COMMON_DIR)

SGX_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc
Wolfssl_Include_Paths := -I$(DEPS_INCLUDE_DIR)

Flags_Just_For_C := -Wno-implicit-function-declaration -std=c11
Common_C_Cpp_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector -fno-builtin -fno-builtin-printf -I. \
										-Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls \
										-Wjump-misses-init -Wstrict-prototypes \
										-Wunsuffixed-float-constants
Wolfssl_C_Extra_Flags := -DSGX_SDK -DWOLFSSL_SGX -DWOLFSSL_SGX_ATTESTATION -DUSER_TIME -DWOLFSSL_CERT_EXT

Tclient_Enclave_C_Flags := $(Flags_Just_For_C) $(Common_C_Cpp_Flags) $(Wolfssl_C_Extra_Flags) -Itrusted $(Wolfssl_Include_Paths) $(SGX_Include_Paths) $(SGX_RA_TLS_Include_Paths)

Crypto_Library_Name := sgx_tcrypto

Tclient_Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) \
	-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-L$(SGX_RA_TLS_LIB) -lratls_attester_t -lratls_challenger_t -lratls_common_t\
	-L$(SGX_WOLFSSL_LIB) -lwolfssl.sgx.static.lib \
		-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=trusted/Tclient_Enclave.lds
### Project Settings ###

### Phony targets ###
.PHONY: all clean

### Build all ###
ifeq ($(Build_Mode), HW_RELEASE)
all: Tclient_Enclave.so
	@echo "Build enclave Tclient_Enclave.so [$(Build_Mode)|$(SGX_ARCH)] success!"
	@echo
	@echo "*********************************************************************************************************************************************************"
	@echo "PLEASE NOTE: In this mode, please sign the Tclient_Enclave.so first using Two Step Sign mechanism before you run the app to launch and access the enclave."
	@echo "*********************************************************************************************************************************************************"
	@echo
else
all: Tclient_Enclave.signed.so
endif

### Sources ###
Tclient_Enclave_C_Files := trusted/Tclient_Enclave.c
Tclient_Enclave_C_Objects := $(Tclient_Enclave_C_Files:.c=.o)

### Edger8r related sourcs ###
trusted/Tclient_Enclave_t.c: $(SGX_EDGER8R) ./trusted/Tclient_Enclave.edl
	@echo Entering ./trusted and execute $(SGX_EDGER8R) --trusted ../trusted/Tclient_Enclave.edl --search-path ../trusted --search-path $(SGX_SDK)/include --search-path ../$(SGX_RA_TLS_COMMON_DIR) --search-path ../$(SGX_RA_TLS_CHALLENGER_DIR) --search-path ../$(SGX_RA_TLS_ATTESTER_DIR)
	@cd ./trusted && $(SGX_EDGER8R) --trusted ../trusted/Tclient_Enclave.edl --search-path ../trusted --search-path $(SGX_SDK)/include --search-path ../$(SGX_RA_TLS_COMMON_DIR) --search-path ../$(SGX_RA_TLS_CHALLENGER_DIR) --search-path ../$(SGX_RA_TLS_ATTESTER_DIR)
	@echo "GEN  =>  $@"

trusted/Tclient_Enclave_t.o: ./trusted/Tclient_Enclave_t.c
	@echo $(CC) $(Tclient_Enclave_C_Flags) -c $< -o $@
	@$(CC) $(Tclient_Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"
### Edger8r related sourcs ###

trusted/%.o: trusted/%.c
	@echo $(CC) $(Tclient_Enclave_C_Flags) -c $< -o $@
	@$(CC) $(Tclient_Enclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

### Enclave Image ###
Tclient_Enclave.so: trusted/Tclient_Enclave_t.o $(Tclient_Enclave_C_Objects)
	@echo $(Tclient_Enclave_Link_Flags)@
	@$(CXX) $^ -o $@ $(Tclient_Enclave_Link_Flags)
	@echo "LINK =>  $@"

### Signing ###
Tclient_Enclave.signed.so: Tclient_Enclave.so
	@$(SGX_ENCLAVE_SIGNER) sign -key trusted/Tclient_Enclave_private.pem -enclave Tclient_Enclave.so -out $@ -config trusted/Tclient_Enclave.config.xml
	@echo "SIGN =>  $@"
### Sources ###

### Clean command ###
clean:
	@rm -f Tclient_Enclave.* trusted/Tclient_Enclave_t.*  $(Tclient_Enclave_C_Objects)
