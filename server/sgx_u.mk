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
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif

APP_DCAP_ATTESTER_LIBS := -lsgx_dcap_ql 
### Intel(R) SGX SDK Settings ###

### Project Settings ###
SGX_RA_TLS_INSTALL_DIR ?= $(abspath ../install)
SGX_RA_TLS_Include_Path := $(SGX_RA_TLS_INSTALL_DIR)/include
SGX_RA_TLS_Lib_Path := $(SGX_RA_TLS_INSTALL_DIR)/lib

Common_C_Cpp_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes -I. \
										-Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls \
										-Wjump-misses-init -Wstrict-prototypes \
										-Wunsuffixed-float-constants
# This flag needed for some wolfssl header
Wolfssl_C_Extra_Flags := -DWOLFSSL_SGX -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_ALWAYS_VERIFY_CB -DKEEP_PEER_CERT -DWOLFSSL_CERT_EXT
Server_App_C_Flags := $(Common_C_Cpp_Flags) $(Wolfssl_C_Extra_Flags) -Iuntrusted -I$(SGX_SDK)/include -I$(SGX_RA_TLS_Include_Path)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        Server_App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        Server_App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        Server_App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif
### Project Settings ###

### Linking setting ###
Server_App_Link_Flags := $(SGX_COMMON_CFLAGS) \
	-L$(SGX_RA_TLS_Lib_Path) -lratls_attester_u -lratls_common_u\
	-L$(SGX_LIBRARY_PATH)	-l$(Urts_Library_Name) $(APP_DCAP_ATTESTER_LIBS) \
	-L$(SGX_RA_TLS_Lib_Path) -l:libcurl-wolfssl.a -l:libwolfssl.a \
	-lpthread -lz -lm

## Add sgx_uae_service library to link ##
ifneq ($(SGX_MODE), HW)
	Server_App_Link_Flags += -lsgx_uae_service_sim
else
	Server_App_Link_Flags += -lsgx_uae_service
endif
### Linking setting ###

### Phony targets ###
.PHONY: all clean

### Build all ###
ifeq ($(Build_Mode), HW_RELEASE)
all: App
	@echo "Build App [$(Build_Mode)|$(SGX_ARCH)] success!"
	@echo
	@echo "*********************************************************************************************************************************************************"
	@echo "PLEASE NOTE: In this mode, please sign the Server_Enclave.so first using Two Step Sign mechanism before you run the app to launch and access the enclave."
	@echo "*********************************************************************************************************************************************************"
	@echo

else
all: App
endif

### Sources ###
Server_App_C_Files := untrusted/App.c
Server_App_C_Objects := $(Server_App_C_Files:.c=.o) untrusted/ra_tls_options.o

## Edger8r related sources ##
untrusted/Server_Enclave_u.c: $(SGX_EDGER8R) trusted/Server_Enclave.edl
	echo $(SGX_MODE)
	cd ./untrusted && $(SGX_EDGER8R) --untrusted ../trusted/Server_Enclave.edl --search-path ../trusted --search-path $(SGX_SDK)/include --search-path $(SGX_RA_TLS_Include_Path)
	@echo "GEN  =>  $@"

untrusted/Server_Enclave_u.o: untrusted/Server_Enclave_u.c
	$(CC) $(Server_App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"
## Edger8r related sources ##

untrusted/%.o: untrusted/%.c
	$(CC) $(Server_App_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

untrusted/ra_tls_options.o: ../option/ra_tls_options.c
	$(CC) $(Server_App_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

## Build server app ##
App: untrusted/Server_Enclave_u.o $(Server_App_C_Objects)
	$(CC) $^ -o $@ $(Server_App_Link_Flags)
	@echo "LINK =>  $@"
### Sources ###

### Clean command ###
clean:
	rm -f App $(Server_App_C_Objects) untrusted/Server_Enclave_u.* 