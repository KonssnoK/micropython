To use wolfSSL with IDF
Partially from https://github.com/wolfSSL/wolfssl/blob/master/IDE/Espressif/ESP-IDF/README.md

- have a working IDF environment
- clone wolfSSL
- run /wolfssl/IDE/Espressif/ESP-IDF/setup.sh

- Go to /esp-idf/components/wolfssl/
- In wolfssl/wolfcrypt/settings.h uncomment WOLFSSL_ESPIDF WOLFSSL_ESPWROOM32 

Overwrite file /wolfssl/include/user_settings.h with the one in this folder