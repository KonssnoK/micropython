/*
 * This file is part of the MicroPython project, http://micropython.org/
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Linaro Ltd.
 * Copyright (c) 2019 Paul Sokolovsky
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

//
#include "wolfssl/ssl.h"
#include "wolfssl/internal.h"

typedef struct _mp_obj_ssl_socket_t {
    mp_obj_base_t base;
    mp_obj_t sock;
    WOLFSSL_CTX* ssl_ctx;
    WOLFSSL* ssl_sock;
} mp_obj_ssl_socket_t;

struct ssl_args {
    mp_arg_val_t key;
    mp_arg_val_t cert;
    mp_arg_val_t cert_reqs;
    mp_arg_val_t ca_certs;
    mp_arg_val_t server_side;
    mp_arg_val_t server_hostname;
    mp_arg_val_t do_handshake;
};

STATIC const mp_obj_type_t ussl_socket_type;

#ifdef MBEDTLS_DEBUG_C
STATIC void mbedtls_debug(void *ctx, int level, const char *file, int line, const char *str) {
    (void)ctx;
    (void)level;
    printf("DBG:%s:%04d: %s\n", file, line, str);
}
#endif

STATIC NORETURN void mbedtls_raise_error(int err) {
    // _mbedtls_ssl_send and _mbedtls_ssl_recv (below) turn positive error codes from the
    // underlying socket into negative codes to pass them through mbedtls. Here we turn them
    // positive again so they get interpreted as the OSError they really are. The
    // cut-off of -256 is a bit hacky, sigh.
    if (err < 0 && err > -256) {
        mp_raise_OSError(-err);
    }

    #if defined(MBEDTLS_ERROR_C)
    // Including mbedtls_strerror takes about 1.5KB due to the error strings.
    // MBEDTLS_ERROR_C is the define used by mbedtls to conditionally include mbedtls_strerror.
    // It is set/unset in the MBEDTLS_CONFIG_FILE which is defined in the Makefile.

    // Try to allocate memory for the message
    #define ERR_STR_MAX 80  // mbedtls_strerror truncates if it doesn't fit
    mp_obj_str_t *o_str = m_new_obj_maybe(mp_obj_str_t);
    byte *o_str_buf = m_new_maybe(byte, ERR_STR_MAX);
    if (o_str == NULL || o_str_buf == NULL) {
        mp_raise_OSError(err);
    }

    // print the error message into the allocated buffer
    mbedtls_strerror(err, (char *)o_str_buf, ERR_STR_MAX);
    size_t len = strlen((char *)o_str_buf);

    // Put the exception object together
    o_str->base.type = &mp_type_str;
    o_str->data = o_str_buf;
    o_str->len = len;
    o_str->hash = qstr_compute_hash(o_str->data, o_str->len);
    // raise
    mp_obj_t args[2] = { MP_OBJ_NEW_SMALL_INT(err), MP_OBJ_FROM_PTR(o_str)};
    nlr_raise(mp_obj_exception_make_new(&mp_type_OSError, 2, 0, args));
    #else
    // mbedtls is compiled without error strings so we simply return the err number
    mp_raise_OSError(err); // err is typically a large negative number
    #endif
}

STATIC int _wolfssl_ssl_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    mp_obj_t sock = *(mp_obj_t *)ctx;

    const mp_stream_p_t *sock_stream = mp_get_stream(sock);
    int err;

    mp_uint_t out_sz = sock_stream->write(sock, buf, sz, &err);
    if (out_sz == MP_STREAM_ERROR) {
        if (mp_is_nonblocking_error(err)) {
            return WOLFSSL_CBIO_ERR_WANT_WRITE;
        }
        return -err; // convert an MP_ERRNO to something mbedtls passes through as error
    } else {
        return out_sz;
    }
}

// _mbedtls_ssl_recv is called by mbedtls to receive bytes from the underlying socket
STATIC int _wolfssl_ssl_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    mp_obj_t sock = *(mp_obj_t *)ctx;

    const mp_stream_p_t *sock_stream = mp_get_stream(sock);
    int err;

    mp_uint_t out_sz = sock_stream->read(sock, buf, sz, &err);
    if (out_sz == MP_STREAM_ERROR) {
        if (mp_is_nonblocking_error(err)) {
            return WOLFSSL_CBIO_ERR_WANT_READ;
        }
        return -err;
    } else {
        return out_sz;
    }
}

STATIC int ssl_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    int ret = 1;
    // TODO
    return ret;
}

STATIC mp_obj_ssl_socket_t *socket_new(mp_obj_t sock, struct ssl_args *args) {
    int err;

    // Verify the socket object has the full stream protocol
    mp_get_stream_raise(sock, MP_STREAM_OP_READ | MP_STREAM_OP_WRITE | MP_STREAM_OP_IOCTL);

    #if MICROPY_PY_USSL_FINALISER
    mp_obj_ssl_socket_t *o = m_new_obj_with_finaliser(mp_obj_ssl_socket_t);
    #else
    mp_obj_ssl_socket_t *o = m_new_obj(mp_obj_ssl_socket_t);
    #endif
    o->base.type = &ussl_socket_type;
    o->sock = sock;

    int ret;

    if ((o->ssl_ctx = wolfSSL_CTX_new(wolfTLS_client_method())) == NULL) {
        mp_raise_OSError(MP_EINVAL);
    }

    // This mimics python load_cert_chain
    if (args->key.u_obj != mp_const_none) {
        size_t len;
        const byte* data = (const byte*)mp_obj_str_get_data(args->key.u_obj, &len);
        // This function loads a private key buffer into the SSL Context.
        if(wolfSSL_CTX_use_PrivateKey_buffer(o->ssl_ctx, data, len, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            mp_raise_ValueError(MP_ERROR_TEXT("invalid key"));
        }
    }
    // This mimics python load_cert_chain
    if (args->cert.u_obj != mp_const_none) {
        size_t len;
        const byte* data = (const byte*)mp_obj_str_get_data(args->cert.u_obj, &len);
        // This function loads a certificate buffer into the WOLFSSL Context.
        if (wolfSSL_CTX_use_certificate_buffer(o->ssl_ctx, data, len, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            mp_raise_ValueError(MP_ERROR_TEXT("invalid cert"));
        }
    }

    // This mimics python load_verify_locations
    if (args->ca_certs.u_obj != mp_const_none) {
        size_t len;
        const byte* data = (const byte*)mp_obj_str_get_data(args->ca_certs.u_obj, &len);
        if (wolfSSL_CTX_load_verify_buffer(o->ssl_ctx, data, len, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            mp_raise_ValueError(MP_ERROR_TEXT("invalid CA cert"));
        }
    }


    int auth_mode = WOLFSSL_VERIFY_NONE;
    if (args->cert_reqs.u_obj != mp_const_none) {
        auth_mode = mp_obj_get_int(args->cert_reqs.u_obj);
    }
    // TODO Other options

    // Set callback for certificate verification
    // SSL_VERIFY_PEER Client mode: the client will verify the certificate received from the server during the handshake.
    wolfSSL_CTX_set_verify(o->ssl_ctx, auth_mode, ssl_verify_callback);

    // This function registers a receive callback for wolfSSL to get input data. 
    wolfSSL_CTX_SetIORecv(o->ssl_ctx, _wolfssl_ssl_recv);
    wolfSSL_CTX_SetIOSend(o->ssl_ctx, _wolfssl_ssl_send);

    o->ssl_sock = wolfSSL_new(o->ssl_ctx);

    // Set blocking socket
    wolfSSL_set_using_nonblock(o->ssl_sock, 0);

    // This function registers a context for the SSL session's receive callback function.
    wolfSSL_SetIOReadCtx(o->ssl_sock, o->ssl_ctx);
    wolfSSL_SetIOWriteCtx(o->ssl_sock, o->ssl_ctx);

    // This function assigns a file descriptor (fd) as the input/output facility for the SSL connection.
    wolfSSL_set_fd(o->ssl_sock, (int)o->sock);

    err = 0; /* reset error */
    ret = wolfSSL_connect(o->ssl_sock);
    if (ret != WOLFSSL_SUCCESS) {
        err = wolfSSL_get_error(o->ssl_sock, 0);
    }

    if (ret != WOLFSSL_SUCCESS) {
        wolfSSL_free(o->ssl_sock);
        wolfSSL_CTX_free(o->ssl_ctx);
    } else {
        mbedtls_raise_error(err);
    }

    return o;
}

STATIC void socket_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind) {
    (void)kind;
    mp_obj_ssl_socket_t *self = MP_OBJ_TO_PTR(self_in);
    mp_printf(print, "<_SSLSocket %p>", self);
}

STATIC mp_uint_t socket_read(mp_obj_t o_in, void *buf, mp_uint_t size, int *errcode) {
    mp_obj_ssl_socket_t *o = MP_OBJ_TO_PTR(o_in);

    int ret = wolfSSL_read(o->ssl_sock, buf, size);
    if (ret == WOLFSSL_CBIO_ERR_CONN_CLOSE) {
        // end of stream
        return 0;
    }
    if (ret >= 0) {
        return ret;
    }
    if (ret == WOLFSSL_CBIO_ERR_WANT_READ) {
        ret = MP_EWOULDBLOCK;
    } else if (ret == WOLFSSL_CBIO_ERR_WANT_WRITE) {
        // If handshake is not finished, read attempt may end up in protocol
        // wanting to write next handshake message. The same may happen with
        // renegotation.
        ret = MP_EWOULDBLOCK;
    }
    *errcode = ret;
    return MP_STREAM_ERROR;
}

STATIC mp_uint_t socket_write(mp_obj_t o_in, const void *buf, mp_uint_t size, int *errcode) {
    mp_obj_ssl_socket_t *o = MP_OBJ_TO_PTR(o_in);

    int ret = wolfSSL_write(o->ssl_sock, buf, size);
    if (ret >= 0) {
        return ret;
    }
    if (ret == WOLFSSL_CBIO_ERR_WANT_WRITE) {
        ret = MP_EWOULDBLOCK;
    } else if (ret == WOLFSSL_CBIO_ERR_WANT_READ) {
        // If handshake is not finished, write attempt may end up in protocol
        // wanting to read next handshake message. The same may happen with
        // renegotation.
        ret = MP_EWOULDBLOCK;
    }
    *errcode = ret;
    return MP_STREAM_ERROR;
}

STATIC mp_obj_t socket_setblocking(mp_obj_t self_in, mp_obj_t flag_in) {
    mp_obj_ssl_socket_t *o = MP_OBJ_TO_PTR(self_in);
    mp_obj_t sock = o->sock;
    mp_obj_t dest[3];
    mp_load_method(sock, MP_QSTR_setblocking, dest);
    dest[2] = flag_in;
    return mp_call_method_n_kw(1, 0, dest);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(socket_setblocking_obj, socket_setblocking);

STATIC mp_uint_t socket_ioctl(mp_obj_t o_in, mp_uint_t request, uintptr_t arg, int *errcode) {
    mp_obj_ssl_socket_t *self = MP_OBJ_TO_PTR(o_in);
    if (request == MP_STREAM_CLOSE) {
        wolfSSL_free(self->ssl_sock);
        wolfSSL_CTX_free(self->ssl_ctx);
    }
    // Pass all requests down to the underlying socket
    return mp_get_stream(self->sock)->ioctl(self->sock, request, arg, errcode);
}

STATIC const mp_rom_map_elem_t ussl_socket_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_read), MP_ROM_PTR(&mp_stream_read_obj) },
    { MP_ROM_QSTR(MP_QSTR_readinto), MP_ROM_PTR(&mp_stream_readinto_obj) },
    { MP_ROM_QSTR(MP_QSTR_readline), MP_ROM_PTR(&mp_stream_unbuffered_readline_obj) },
    { MP_ROM_QSTR(MP_QSTR_write), MP_ROM_PTR(&mp_stream_write_obj) },
    { MP_ROM_QSTR(MP_QSTR_setblocking), MP_ROM_PTR(&socket_setblocking_obj) },
    { MP_ROM_QSTR(MP_QSTR_close), MP_ROM_PTR(&mp_stream_close_obj) },
    #if MICROPY_PY_USSL_FINALISER
    { MP_ROM_QSTR(MP_QSTR___del__), MP_ROM_PTR(&mp_stream_close_obj) },
    #endif
};

STATIC MP_DEFINE_CONST_DICT(ussl_socket_locals_dict, ussl_socket_locals_dict_table);

STATIC const mp_stream_p_t ussl_socket_stream_p = {
    .read = socket_read,
    .write = socket_write,
    .ioctl = socket_ioctl,
};

STATIC const mp_obj_type_t ussl_socket_type = {
    { &mp_type_type },
    // Save on qstr's, reuse same as for module
    .name = MP_QSTR_ussl,
    .print = socket_print,
    .getiter = NULL,
    .iternext = NULL,
    .protocol = &ussl_socket_stream_p,
    .locals_dict = (void *)&ussl_socket_locals_dict,
};

STATIC mp_obj_t mod_ssl_wrap_socket(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {
    // TODO: Implement more args
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_key, MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_rom_obj = MP_ROM_NONE} },
        { MP_QSTR_cert_reqs, MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_rom_obj = MP_ROM_NONE} },
        { MP_QSTR_cert, MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_rom_obj = MP_ROM_NONE} },
        { MP_QSTR_ca_certs, MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_rom_obj = MP_ROM_NONE} },
        { MP_QSTR_server_side, MP_ARG_KW_ONLY | MP_ARG_BOOL, {.u_bool = false} },
        { MP_QSTR_server_hostname, MP_ARG_KW_ONLY | MP_ARG_OBJ, {.u_rom_obj = MP_ROM_NONE} },
        { MP_QSTR_do_handshake, MP_ARG_KW_ONLY | MP_ARG_BOOL, {.u_bool = true} },
    };

    // TODO: Check that sock implements stream protocol
    mp_obj_t sock = pos_args[0];

    struct ssl_args args;
    mp_arg_parse_all(n_args - 1, pos_args + 1, kw_args,
        MP_ARRAY_SIZE(allowed_args), allowed_args, (mp_arg_val_t *)&args);

    return MP_OBJ_FROM_PTR(socket_new(sock, &args));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_KW(mod_ssl_wrap_socket_obj, 1, mod_ssl_wrap_socket);

STATIC const mp_rom_map_elem_t mp_module_ssl_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_ussl) },
    { MP_ROM_QSTR(MP_QSTR_wrap_socket), MP_ROM_PTR(&mod_ssl_wrap_socket_obj) },
    // class Constants
    { MP_ROM_QSTR(MP_QSTR_CERT_NONE), MP_ROM_INT(WOLFSSL_VERIFY_NONE)},
    { MP_ROM_QSTR(MP_QSTR_CERT_OPTIONAL), MP_ROM_INT(WOLFSSL_VERIFY_PEER)},
    { MP_ROM_QSTR(MP_QSTR_CERT_REQUIRED), MP_ROM_INT(WOLFSSL_VERIFY_PEER)},
};

STATIC MP_DEFINE_CONST_DICT(mp_module_ssl_globals, mp_module_ssl_globals_table);

const mp_obj_module_t mp_module_ussl = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_ssl_globals,
};

#endif // MICROPY_PY_USSL
