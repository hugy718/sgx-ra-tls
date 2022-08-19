# Makefile to build non-SGX-SDK-based RA-TLS client and server
# programs.
export SGX_SDK ?= /opt/intel/sgxsdk

### Variable Settings ###
CFLAGS+=-std=gnu99 -I. -I$(SGX_SDK)/include -Ideps/local/include -fPIC
## error flags ##
CFLAGSERRORS=-Wall -Wextra -Wwrite-strings -Wshadow -Werror
## wolfssl build flags ##
CFLAGS+=$(CFLAGSERRORS) -g -O0 -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_CERT_EXT
## challenger checks if group out of data is stated in IAS report ##
CFLAGS+=-DSGX_GROUP_OUT_OF_DATE
### Variable Settings ###

### Phony targets ###
.PHONY: all deps ratls_libs clients server clean mrproper 

### IAS EPID configuration ###
option/ra_tls_options.c: option/ra_tls_options.c.sh
	bash $^ > $@

### Build dependencies ###
## wolfssl ##
deps/wolfssl/configure:
	cd deps && git clone https://github.com/wolfSSL/wolfssl
	cd deps/wolfssl && git checkout 57e5648a5dd734d1c219d385705498ad12941dd0
	cd deps/wolfssl && patch -p1 < ../../ra/wolfssl.patch
	cd deps/wolfssl && ./autogen.sh

WOLFSSL_CFLAGS+=-DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_ALWAYS_VERIFY_CB -DKEEP_PEER_CERT
WOLFSSL_CONFIGURE_FLAGS+=--prefix=$(shell readlink -f deps/local) --enable-writedup --enable-static --enable-keygen --enable-certgen --enable-certext --with-pic --disable-examples --disable-crypttests --enable-aesni --enable-tlsv10
ifdef DEBUG
WOLFSSL_CFLAGS+=--enable-debug
endif

deps/local/lib/libwolfssl.a: CFLAGS+= $(WOLFSSL_CFLAGS)
deps/local/lib/libwolfssl.a: deps/wolfssl/configure
	cd deps/wolfssl && CC=gcc-5 CFLAGS="$(CFLAGS)" ./configure $(WOLFSSL_CONFIGURE_FLAGS)
	cd deps/wolfssl && $(MAKE) install

## curl ##
deps/curl/configure:
	cd deps && git clone https://github.com/curl/curl.git
	cd deps/curl && git checkout curl-7_47_0
	cd deps/curl && ./buildconf

CURL_CONFFLAGS=--prefix=$(shell readlink -f deps/local) --without-libidn --without-librtmp --without-libssh2 --without-libmetalink --without-libpsl --disable-ldap --disable-ldaps --disable-shared
ifdef DEBUG
CURL_CONFFLAGS+=--enable-debug
endif

deps/local/lib/libcurl-wolfssl.a: deps/curl/configure deps/local/lib/libwolfssl.a
	cp -a deps/curl deps/curl-wolfssl
	cd deps/curl-wolfssl && CFLAGS="-fPIC" ./configure $(CURL_CONFFLAGS) --without-ssl --with-cyassl=$(shell readlink -f deps/local)
	cd deps/curl-wolfssl && $(MAKE) && $(MAKE) install
	cp deps/curl-wolfssl/lib/.libs/libcurl.a deps/local/lib/libcurl-wolfssl.a

deps: deps/local/lib/libcurl-wolfssl.a 
### Build dependencies ###

### Build ra-tls libs ###
lib:
	mkdir -p $@

ratls_libs: lib
	$(MAKE) -C ra all
	cp ra/*.a ./lib
### Build ra-tls libs ###

### Build client ###
WOLFSSL_CLIENT_LIBS=-l:libratls_challenger.a -l:libratls_common_u.a -l:libwolfssl.a -lm

wolfssl-client: client/client-tls.c ratls_libs
	$(CC) -o $@ $(filter %.c, $^) $(CFLAGS) -I./ra/include -Llib -Ldeps/local/lib $(WOLFSSL_CLIENT_LIBS)

clients: wolfssl-client mtclient
### Build client ###

### Build wolfssl Linux SGX support ###
deps/local/lib/libwolfssl.sgx.static.lib.a: deps/local/lib/libwolfssl.a
	cd deps/wolfssl/IDE/LINUX-SGX && make -f sgx_t_static.mk CFLAGS="-DUSER_TIME -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_KEY_GEN -DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT -DFP_MAX_BITS=8192"
	mkdir -p deps/local/lib && cp deps/wolfssl/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a deps/local/lib

### Build server ###
enclave-app: deps/local/lib/libwolfssl.sgx.static.lib.a ratls_libs
	$(MAKE) -C server SGX_MODE=HW SGX_DEBUG=0 SGX_PRERELEASE=1 SGX_WOLFSSL_LIB=$(shell readlink -f deps/local/lib) SGX_SDK=$(SGX_SDK) DEPS_INCLUDE_DIR=$(shell readlink -f deps/local/include) SGX_RA_TLS_LIB=$(shell readlink -f lib/)

server: enclave-app mserver
### Build server ###

### Build server with mutual attestation ###
mserver: deps/local/lib/libwolfssl.sgx.static.lib.a ratls_libs
	$(MAKE) -C mserver SGX_MODE=HW SGX_DEBUG=0 SGX_PRERELEASE=1 SGX_WOLFSSL_LIB=$(shell readlink -f deps/local/lib) SGX_SDK=$(SGX_SDK) DEPS_INCLUDE_DIR=$(shell readlink -f deps/local/include) SGX_RA_TLS_LIB=$(shell readlink -f lib/)
### Build server with mutual attestation ###

### Build client with mutual attestation ###
mtclient: deps/local/lib/libwolfssl.sgx.static.lib.a ratls_libs
	$(MAKE) -C mtclient SGX_MODE=HW SGX_DEBUG=0 SGX_PRERELEASE=1 SGX_WOLFSSL_LIB=$(shell readlink -f deps/local/lib) SGX_SDK=$(SGX_SDK) DEPS_INCLUDE_DIR=$(shell readlink -f deps/local/include) SGX_RA_TLS_LIB=$(shell readlink -f lib/)
### Build client with mutual attestation ###


### Build all ###
all: deps clients server

### clean commands ###
clean:
	$(RM) wolfssl-client
	$(RM) option/*.o 
	$(MAKE) -C ra clean
	$(MAKE) -C server clean
	$(MAKE) -C mserver clean
	$(MAKE) -C mtclient clean
	$(RM) -rf lib

mrproper: clean
	$(MAKE) -C ra mrproper
	$(RM) -rf lib
	$(RM) -rf deps
	$(RM) wolfssl-client
	$(MAKE) -C server clean
	$(MAKE) -C mserver clean
	$(MAKE) -C mtclient clean
	$(RM) option/ra_tls_options.c
### clean commands ###
