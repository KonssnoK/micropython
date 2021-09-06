#pragma once

//Target 21k build -> from https://www.wolfssl.com/forums/topic697-building-leanpsk-in-a-nonstandard-environment.html
#define WOLFSSL_LEANPSK
#define HAVE_NULL_CIPHER
#define SINGLE_THREADED
//#define NO_AES
#define NO_FILESYSTEM
#define NO_RABBIT
//#define NO_RSA
#define NO_DSA
#define NO_DH
//#define NO_CERTS
#define NO_PWDBASED
#define NO_DES3
#define NO_MD4
#define NO_MD5
#define NO_ERROR_STRINGS
#define NO_OLD_TLS
#define NO_RC4
#define NO_WRITEV
#define NO_SESSION_CACHE
#define NO_DEV_RANDOM
#define WOLFSSL_USER_IO
//#define NO_SHA
#define USE_SLOW_SHA
#define BUILD_SLOWMATH
#define SINGLE_THREADED

// TLS1.3 and additional options
#define WC_RSA_PSS
#define HAVE_TLS_EXTENSIONS
#define WOLFSSL_TLS13
#define HAVE_SUPPORTED_CURVES
#define WOLFSSL_NO_TLS12
#define NO_OLD_SSL_NAMES
#define HAVE_ECC
#define HAVE_HKDF
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_CERT_GEN
#define NO_WOLFSSL_SERVER
#define WC_NO_HARDEN // TODO CHECK for Timing resistance
#define WOLFSSL_NO_PEM
#define CUSTOM_RAND_GENERATE system_get_time
extern int system_get_time();

#define CTYPE_USER
#define XTOLOWER toLower
#define XTOUPPER toUpper
char toLower(char chr);
char toUpper(char chr);

//#define TIME_OVERRIDES
#define USER_TIME
#define WOLFSSL_GMTIME
#define USE_WOLF_SUSECONDS_T
#define USE_WOLF_TIMEVAL_T
#define USER_TICKS
