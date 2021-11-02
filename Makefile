# Makefile to build non-SGX-SDK-based RA-TLS client and server
# programs.

export SGX_SDK?=/opt/intel/sgxsdk

CFLAGS+=-std=gnu99 -I. -I$(SGX_SDK)/include -Ideps/local/include -fPIC
CFLAGSERRORS=-Wall -Wextra -Wwrite-strings -Wshadow -Werror
CFLAGS+=$(CFLAGSERRORS) -g -O0 -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_CERT_EXT # -DDEBUG -DDYNAMIC_RSA
CFLAGS+=-DSGX_GROUP_OUT_OF_DATE

.PHONY: all deps clients server clean mrproper 

option/ra_tls_options.c: option/ra_tls_options.c.sh
	bash $^ > $@

# Build dependencies
deps/curl/configure:
	cd deps && git clone https://github.com/curl/curl.git
	cd deps/curl && git checkout curl-7_47_0
	cd deps/curl && ./buildconf

deps/wolfssl/configure:
	cd deps && git clone https://github.com/wolfSSL/wolfssl
	cd deps/wolfssl && git checkout 57e5648a5dd734d1c219d385705498ad12941dd0
	cd deps/wolfssl && patch -p1 < ../../ra/wolfssl.patch
	cd deps/wolfssl && ./autogen.sh

# Add --enable-debug to ./configure for debug build
# WOLFSSL_ALWAYS_VERIFY_CB ... Always call certificate verification callback, even if verification succeeds
# KEEP_OUR_CERT ... Keep the certificate around after the handshake
# --enable-tlsv10 ... required by libcurl
# 2019-03-19 removed --enable-intelasm configure flag. The Celeron NUC I am developing this, does not support AVX.
WOLFSSL_CFLAGS+=-DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_ALWAYS_VERIFY_CB -DKEEP_PEER_CERT
WOLFSSL_CONFIGURE_FLAGS+=--prefix=$(shell readlink -f deps/local) --enable-writedup --enable-static --enable-keygen --enable-certgen --enable-certext --with-pic --disable-examples --disable-crypttests --enable-aesni --enable-tlsv10
ifdef DEBUG
WOLFSSL_CFLAGS+=--enable-debug
endif

deps/local/lib/libwolfssl.a: CFLAGS+= $(WOLFSSL_CFLAGS)
deps/local/lib/libwolfssl.a: deps/wolfssl/configure
# Force the use of gcc-5. Later versions of gcc report errors on this version of wolfSSL.
# TODO: Upgrade to more recent version of wolfSSL.
	cd deps/wolfssl && CC=gcc-5 CFLAGS="$(CFLAGS)" ./configure $(WOLFSSL_CONFIGURE_FLAGS)
	cd deps/wolfssl && $(MAKE) install

CURL_CONFFLAGS=--prefix=$(shell readlink -f deps/local) --without-libidn --without-librtmp --without-libssh2 --without-libmetalink --without-libpsl --disable-ldap --disable-ldaps --disable-shared
ifdef DEBUG
CURL_CONFFLAGS+=--enable-debug
endif

deps/local/lib/libcurl-wolfssl.a: deps/curl/configure deps/local/lib/libwolfssl.a
	cp -a deps/curl deps/curl-wolfssl
	cd deps/curl-wolfssl && CFLAGS="-fPIC" ./configure $(CURL_CONFFLAGS) --without-ssl --with-cyassl=$(shell readlink -f deps/local)
	cd deps/curl-wolfssl && $(MAKE)
	cp deps/curl-wolfssl/lib/.libs/libcurl.a deps/local/lib/libcurl-wolfssl.a

deps: deps/local/lib/libcurl-wolfssl.a 


# Build client from wolfssl-example repo
lib:
	mkdir -p $@

lib/libra-challenger.a: lib ra/ra.o ra/wolfssl-ra-challenger.o ra/wolfssl-ra.o ra/ra-challenger.o ra/ias_sign_ca_cert.o
	$(AR) rcs $@ $(filter %.o, $^)

WOLFSSL_CLIENT_LIBS=-l:libra-challenger.a -l:libwolfssl.a -lm

wolfssl-client: client/client-tls.c lib/libra-challenger.a
	$(CC) -o $@ $(filter %.c, $^) $(CFLAGS) -Llib -Ldeps/local/lib $(WOLFSSL_CLIENT_LIBS)

clients: wolfssl-client

# Ideally, deps/wolfssl/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a and
# deps/local/lib/libwolfssl.a could be built in parallel. Does not
# work however. Hence, the dependency forces a serial build.
#
# -DFP_MAX_BITS=8192 required for RSA keys > 2048 bits to work
deps/local/lib/libwolfssl.sgx.static.lib.a: deps/local/lib/libwolfssl.a
	cd deps/wolfssl/IDE/LINUX-SGX && make -f sgx_t_static.mk CFLAGS="-DUSER_TIME -DWOLFSSL_SGX_ATTESTATION -DWOLFSSL_KEY_GEN -DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT -DFP_MAX_BITS=8192"
	mkdir -p deps/local/lib && cp deps/wolfssl/IDE/LINUX-SGX/libwolfssl.sgx.static.lib.a deps/local/lib

# build wolfssl-sgx library
libsgx_ra_tls_wolfssl.a: lib
	cd ra && make -f ratls-wolfssl.mk clean || { cd ..; exit 1; }
	cd ra && make -f ratls-wolfssl.mk
	cd ra && make -f ratls-wolfssl.mk clean || { cd ..; exit 1; }
	cp ra/libsgx_ra_tls_wolfssl.a ./lib

# build server
enclave-app: deps/local/lib/libwolfssl.sgx.static.lib.a libsgx_ra_tls_wolfssl.a ra/sgxsdk-ra-attester_u.c ra/ias-ra.c
	cp ra/sgxsdk-ra-attester_u.c ra/ias-ra.c server/untrusted
	$(MAKE) -C server SGX_MODE=HW SGX_DEBUG=1 SGX_WOLFSSL_LIB=$(shell readlink -f deps/local/lib) SGX_SDK=$(SGX_SDK) WOLFSSL_ROOT=$(shell readlink -f deps/wolfssl) SGX_RA_TLS_LIB=$(shell readlink -f lib/)

server: enclave-app

all: deps clients server

clean:
	$(RM) *.o
	$(RM) lib/*

mrproper: clean
	cd ra; $(MAKE) -f ratls-wolfssl.mk mrproper; cd ..
	$(RM) $(EXECS) 
	$(RM) -rf lib
	$(RM) -rf deps
	$(RM) wolfssl-client
	$(MAKE) -C server clean
	$(RM) option/ra_tls_options.c
