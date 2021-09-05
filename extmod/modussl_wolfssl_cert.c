/*
 * This file is part of the MicroPython project, http://micropython.org/
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2021 Lorenzo Consolaro
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "py/mpconfig.h"
#if MICROPY_PY_USSL && MICROPY_SSL_WOLFSSL

#include <stdio.h>
#include <string.h>
#include <errno.h> // needed because mp_is_nonblocking_error uses system error codes

#include "py/runtime.h"
#include "py/stream.h"
#include "py/objstr.h"

// Wolfssl includes
#include "wolfssl/ssl.h"
#include "wolfssl/internal.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/rsa.h"

typedef struct _mp_obj_ssl_certificate_t {
    mp_obj_base_t base;
    Cert ssCert;
    RsaKey key;
    WC_RNG rng;
} mp_obj_ssl_certificate_t;

STATIC const mp_obj_type_t usslcert_certificate_type;// Declared at the end

STATIC mp_obj_t usslcert_certificate_new(const mp_obj_type_t* type, size_t n_args, size_t n_kw, const mp_obj_t* all_args)
{
    (void)type;
    (void)n_args;
    (void)n_kw;
    (void)all_args;

    mp_obj_ssl_certificate_t* o = m_new_obj(mp_obj_ssl_certificate_t);

    o->base.type = &usslcert_certificate_type;

    return o;
}

STATIC mp_obj_t usslcert_certificate_subject_country(size_t n_args, const mp_obj_t* args)
{
    mp_obj_ssl_certificate_t* self = MP_OBJ_TO_PTR(args[0]);

    if (n_args == 2) {
        // 
        size_t len;
        const char* data = (const char*)mp_obj_str_get_data(args[1], &len);
        memset(self->ssCert.subject.country, 0, CTC_NAME_SIZE);
        strncpy(self->ssCert.subject.country, data, len);
    }
    // Return current value.
    return mp_obj_new_str(self->ssCert.subject.country, CTC_NAME_SIZE);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(usslcert_certificate_subject_country_obj, 1, 2, usslcert_certificate_subject_country);

STATIC mp_obj_t usslcert_certificate_subject_state(size_t n_args, const mp_obj_t* args)
{
    mp_obj_ssl_certificate_t* self = MP_OBJ_TO_PTR(args[0]);

    if (n_args == 2) {
        // 
        size_t len;
        const char* data = (const char*)mp_obj_str_get_data(args[1], &len);
        memset(self->ssCert.subject.state, 0, CTC_NAME_SIZE);
        strncpy(self->ssCert.subject.state, data, len);
    }
    // Return current value.
    return mp_obj_new_str(self->ssCert.subject.country, CTC_NAME_SIZE);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(usslcert_certificate_subject_state_obj, 1, 2, usslcert_certificate_subject_state);

STATIC mp_obj_t usslcert_certificate_subject_locality(size_t n_args, const mp_obj_t* args)
{
    mp_obj_ssl_certificate_t* self = MP_OBJ_TO_PTR(args[0]);

    if (n_args == 2) {
        // 
        size_t len;
        const char* data = (const char*)mp_obj_str_get_data(args[1], &len);
        memset(self->ssCert.subject.locality, 0, CTC_NAME_SIZE);
        strncpy(self->ssCert.subject.locality, data, len);
    }
    // Return current value.
    return mp_obj_new_str(self->ssCert.subject.locality, CTC_NAME_SIZE);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(usslcert_certificate_subject_locality_obj, 1, 2, usslcert_certificate_subject_locality);

STATIC mp_obj_t usslcert_certificate_subject_org(size_t n_args, const mp_obj_t* args)
{
    mp_obj_ssl_certificate_t* self = MP_OBJ_TO_PTR(args[0]);

    if (n_args == 2) {
        // 
        size_t len;
        const char* data = (const char*)mp_obj_str_get_data(args[1], &len);
        memset(self->ssCert.subject.org, 0, CTC_NAME_SIZE);
        strncpy(self->ssCert.subject.org, data, len);
    }
    // Return current value.
    return mp_obj_new_str(self->ssCert.subject.org, CTC_NAME_SIZE);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(usslcert_certificate_subject_org_obj, 1, 2, usslcert_certificate_subject_org);

STATIC mp_obj_t usslcert_certificate_subject_commonName(size_t n_args, const mp_obj_t* args)
{
    mp_obj_ssl_certificate_t* self = MP_OBJ_TO_PTR(args[0]);

    if (n_args == 2) {
        // 
        size_t len;
        const char* data = (const char*)mp_obj_str_get_data(args[1], &len);
        memset(self->ssCert.subject.commonName, 0, CTC_NAME_SIZE);
        strncpy(self->ssCert.subject.commonName, data, len);
    }
    // Return current value.
    return mp_obj_new_str(self->ssCert.subject.commonName, CTC_NAME_SIZE);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(usslcert_certificate_subject_commonName_obj, 1, 2, usslcert_certificate_subject_commonName);

STATIC mp_obj_t usslcert_certificate_daysValid(size_t n_args, const mp_obj_t* args)
{
    mp_obj_ssl_certificate_t* self = MP_OBJ_TO_PTR(args[0]);

    if (n_args == 2) {
        //
        int days = mp_obj_get_int(args[1]);
        self->ssCert.daysValid = days;
    }
    // Return current value.
    return mp_obj_new_int(self->ssCert.daysValid);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(usslcert_certificate_daysValid_obj, 1, 2, usslcert_certificate_daysValid);

STATIC mp_obj_t usslcert_certificate_isCA(size_t n_args, const mp_obj_t* args)
{
    mp_obj_ssl_certificate_t* self = MP_OBJ_TO_PTR(args[0]);

    if (n_args == 2) {
        //  
        self->ssCert.isCA = 0;
        if (mp_obj_is_true(args[1])) {
            self->ssCert.isCA = 1;
        }
    }
    // Return current value.
    return mp_obj_new_int(self->ssCert.isCA);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(usslcert_certificate_isCA_obj, 1, 2, usslcert_certificate_isCA);

STATIC mp_obj_t usslcert_certificate_sigType(size_t n_args, const mp_obj_t* args)
{
    mp_obj_ssl_certificate_t* self = MP_OBJ_TO_PTR(args[0]);

    if (n_args == 2) {
        //
        int value = mp_obj_get_int(args[1]);
        self->ssCert.sigType = value;
    }
    // Return current value.
    return mp_obj_new_int(self->ssCert.sigType);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(usslcert_certificate_sigType_obj, 1, 2, usslcert_certificate_sigType);

STATIC mp_obj_t usslcert_certificate_serial(size_t n_args, const mp_obj_t* args)
{
    mp_obj_ssl_certificate_t* self = MP_OBJ_TO_PTR(args[0]);

    if (n_args == 2) {
        // 
        size_t len;
        const byte* data = (const byte*)mp_obj_str_get_data(args[1], &len);

        memset(self->ssCert.serial, 0, CTC_SERIAL_SIZE);
        memcpy(self->ssCert.serial, data, len);
        self->ssCert.serialSz = len;
    }
    // Return current value.
    return mp_obj_new_bytearray(self->ssCert.serialSz, self->ssCert.serial);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(usslcert_certificate_serial_obj, 1, 2, usslcert_certificate_serial);

/// ////////////////////////////////////////////////////////

STATIC const mp_rom_map_elem_t usslcert_certificate_locals_dict_table[] = {
    // Class methods
    { MP_ROM_QSTR(MP_QSTR_subject_country   ), MP_ROM_PTR(&usslcert_certificate_subject_country_obj) },
    { MP_ROM_QSTR(MP_QSTR_subject_state     ), MP_ROM_PTR(&usslcert_certificate_subject_state_obj) },
    { MP_ROM_QSTR(MP_QSTR_subject_locality  ), MP_ROM_PTR(&usslcert_certificate_subject_locality_obj) },
    { MP_ROM_QSTR(MP_QSTR_subject_org       ), MP_ROM_PTR(&usslcert_certificate_subject_org_obj) },
    { MP_ROM_QSTR(MP_QSTR_subject_commonName), MP_ROM_PTR(&usslcert_certificate_subject_commonName_obj) },
    { MP_ROM_QSTR(MP_QSTR_daysValid         ), MP_ROM_PTR(&usslcert_certificate_daysValid_obj) },
    { MP_ROM_QSTR(MP_QSTR_isCA              ), MP_ROM_PTR(&usslcert_certificate_isCA_obj) },
    { MP_ROM_QSTR(MP_QSTR_sigType           ), MP_ROM_PTR(&usslcert_certificate_sigType_obj) },
    { MP_ROM_QSTR(MP_QSTR_serial            ), MP_ROM_PTR(&usslcert_certificate_serial_obj) },
};
STATIC MP_DEFINE_CONST_DICT(usslcert_certificate_locals_dict, usslcert_certificate_locals_dict_table);

STATIC const mp_obj_type_t usslcert_certificate_type = {
    // Class declaration
    { &mp_type_type },
    .name = MP_QSTR_certificate,
    .make_new = usslcert_certificate_new,
    .locals_dict = (void*)&usslcert_certificate_locals_dict,
};

/////////////////////////////////////////////////////////

STATIC mp_obj_t usslcert_cert_init(mp_obj_t cert)
{
    mp_obj_ssl_certificate_t* self = MP_OBJ_TO_PTR(cert);
    int ret;

    ret = wc_InitCert(&self->ssCert);
    if (ret) {
        mp_raise_ValueError(MP_ERROR_TEXT("cannot init Cert"));
    }

    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(usslcert_cert_init_obj, usslcert_cert_init);

STATIC mp_obj_t usslcert_cert_selfsign(mp_obj_t cert, mp_obj_t private_key)
{
#define TWOK_BUF 0x800
    mp_obj_ssl_certificate_t* self = MP_OBJ_TO_PTR(cert);
    int ret;
    size_t key_len;
    const byte* key_data = (const byte*)mp_obj_str_get_data(private_key, &key_len);
    uint32_t idx;
    byte* derCert = m_new(byte, TWOK_BUF);
    int derCertSz;

    // Initialize RSA Struct
    ret = wc_InitRsaKey(&self->key, 0);
    if (ret) {
        mp_raise_ValueError(MP_ERROR_TEXT("cannot init RSA key"));
    }

    // Extract key from DER and put it in the RSA struct
    ret = wc_RsaPrivateKeyDecode(
        key_data,
        &idx,
        &self->key,
        key_len
    );
    if (ret) {
        mp_raise_ValueError(MP_ERROR_TEXT("cannot decode key"));
    }

    // Initialize random generator
    ret = wc_InitRng(&self->rng);
    if (ret) {
        mp_raise_ValueError(MP_ERROR_TEXT("cannot init RNG"));
    }

    derCertSz = wc_MakeSelfCert(
        &self->ssCert,
        derCert,
        TWOK_BUF,
        &self->key,
        &self->rng
    );

    //Free resources
    wc_FreeRng(&self->rng);

    if (derCertSz < 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("cannot selfsign certificate"));
    } else {
        m_renew(byte, derCert, TWOK_BUF, derCertSz);

        return mp_obj_new_bytearray_by_ref(derCertSz, derCert);
    }

    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(usslcert_cert_selfsign_obj, usslcert_cert_selfsign);


STATIC const mp_rom_map_elem_t mp_module_usslcert_globals_table[] = {
    // Module methods
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_usslcert) },   //Import name
    { MP_ROM_QSTR(MP_QSTR_certificate), MP_ROM_PTR(&usslcert_certificate_type) },     //Certificate class
    // Module methods
    { MP_ROM_QSTR(MP_QSTR_cert_init     ), MP_ROM_PTR(&usslcert_cert_init_obj) },
    { MP_ROM_QSTR(MP_QSTR_cert_selfsign ), MP_ROM_PTR(&usslcert_cert_selfsign_obj) },
    // Modules defines
    { MP_ROM_QSTR(MP_QSTR_CTC_SHA256wRSA), MP_ROM_INT(CTC_SHA256wRSA)},
};

STATIC MP_DEFINE_CONST_DICT(mp_module_usslcert_globals, mp_module_usslcert_globals_table);

const mp_obj_module_t mp_module_usslcert = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t*)&mp_module_usslcert_globals,
};

#endif // MICROPY_PY_USSL
