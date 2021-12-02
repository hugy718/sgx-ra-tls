# RA Library

This serves as an overview of all files except client and server. The files will be marked as (u or u/t), indicating whether they can be used in the untrusted code only or both.

## common
* ra.h (u) - define the struct attestation_verification_report_t
* wolfssl-ra.h (u/t) - produce the sha256 of rsa public key. used by both attester and challenger. implemented by wolfssl-ra.c
* wolfssl-ra.c - implement wolfssl-ra.h and implement the dummy function to appease edger8r with ra_tls.edl.
ias-ra.h
* ra_private.h 
  * - do remote attestation api. used by attester (t)
  * - OID used by ra challenger for report decoding. implemented by ra.c used by challenger (u)  
* ra.c (u/t) - implement ra.h OID variables
## attester
* curl_helper.h (u) - use curl to perfrom http get. used to get attestation report from ias. implemented by ias-ra.c
* ias-ra.h (u) - obtain attestation report used by attester. implemented by ra.c
* ias-ra.c (u) - implement ra.h and curl_helper.c
* ra-attester.h - interface
* wolfssl-ra-attester.h (u/t)- expose an additional wolfssl_create_key_and_x509. but no one use
* wolfssl-ra-attester.c (u/t) - implements ra-attester.h

## challenger
* ias_sign_ca_cert.c (u/t) - the ias ca certificate
* ra-challenger.h interface
* ra-challenger_private.h - process the x509 extension, again the OID variables (but now for challenger)
* ra-challenger.c (u/t) - implement ra-challenger_private.h
* wolfssl-ra-challenger (u/t) - implements ra-challenger.h
