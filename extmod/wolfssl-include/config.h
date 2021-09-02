#pragma once

//Target 21k build
#define WOLFSSL_LEANPSK
#define HAVE_NULL_CIPHER
#define SINGLE_THREADED
#define NO_AES
#define NO_FILESYSTEM
#define NO_RABBIT
#define NO_RSA
#define NO_DSA
#define NO_DH
#define NO_CERTS
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
#define NO_SHA
#define USE_SLOW_SHA
#define BUILD_SLOWMATH
#define SINGLE_THREADED

#define NO_OLD_SSL_NAMES