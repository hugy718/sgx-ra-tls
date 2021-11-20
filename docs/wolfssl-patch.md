## WolfSSL Patch
The patch is provided for a wolfssl version in 2017. Some fixes has been incorporated by later wolfssl versions. Here, we only discuss the modification to enable remote attestation.

### wolfcrypt/settings.h
Originally when compiled with WOLFSSL_SGX, NO_ASN_TIME is defined to "disable time parts of the ASN code for systems without an RTC or wishing to save space" (from [asn.c](wolfcrypt/src/asn.c)). It is undefined. This is related for checking the time validity.

### wolfssl/internal.h
The max size of a handshake message MAX_HANDSHAKE_SZ is set to 4 times the MAX_CERTIFICATE_SZ, to accomodate the IAS report.

### wolfssl/wolfcrypt/asn_public.h
`Cert` is added with fields to include information for remote attestation.
* iasSigCACert
* iasSigCert    
* iasSig    
* iasAttestationReport
* quote   
* pckCrt    
* pckSignChain    
* tcbInfo    
* tcbSignChain    
* qeIdentity    
* rootCaCrl    
* pckCrl    

### wolfssl/asn.c
1. `DerCert` DER encoded x509 certificate struct is also extended with the above information.
2. Diable the use of `mktime()` in `SetValidity()` function inside enclave and relies on the `RebuildTime()` function implemented by wolfssl to calender time representation (`time_t`).
3. Hardcode certificate validity period in `SetValidity()`, due to the lack of trusted time source inside enclave. This has been updated while sgx-ra-tls is developed. Now the valid period is 15 Feb 2020 (the last commit to the repo) to 15 Feb 2030. User need to make a decision on this.
4. `SetObjectIdValue()` is made non-static. (not sure why this removal of internal linkage restriction is needed. It is not used elsewhere.)
5. Define and implement new static function`SetSGXExt()`. Add the SGX extension with ASN_SEQUENCE tag, ASN_CONSTRUCTED flag. Add object id. Add the octet header )(with length of extension). Add the extension input.
6. Extend `EncodeCert()` to use `SetSGXExt()` to fill up the DER encoded certificate from a certificate source. The chain of caller functions that uses it is `wc_MakeSelfCert()-> wc_MakeCert() -> MakeAnyCert()`. The `generate_x509()` function in [wolfssl-ra-attester.c](ra/wolfssl-ra-attester.c) calls it.