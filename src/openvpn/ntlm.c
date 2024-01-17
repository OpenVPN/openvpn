/*
 *  ntlm proxy support for OpenVPN
 *
 *  Copyright (C) 2004 William Preston
 *
 *  *NTLMv2 support and domain name parsing by Miroslav Zajic, Nextsoft s.r.o.*
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#if NTLM

#include "common.h"
#include "buffer.h"
#include "misc.h"
#include "socket.h"
#include "fdmisc.h"
#include "proxy.h"
#include "ntlm.h"
#include "base64.h"
#include "crypto.h"

#include "memdbg.h"


/* 64bit datatype macros */
#ifdef _MSC_VER
/* MS compilers */
#define UINTEGER64 __int64
#define UINT64(c) c ## Ui64
#else
/* Non MS compilers */
#define UINTEGER64 unsigned long long
#define UINT64(c) c ## LL
#endif



static void
create_des_keys(const unsigned char *hash, unsigned char *key)
{
    key[0] = hash[0];
    key[1] = ((hash[0] & 1) << 7) | (hash[1] >> 1);
    key[2] = ((hash[1] & 3) << 6) | (hash[2] >> 2);
    key[3] = ((hash[2] & 7) << 5) | (hash[3] >> 3);
    key[4] = ((hash[3] & 15) << 4) | (hash[4] >> 4);
    key[5] = ((hash[4] & 31) << 3) | (hash[5] >> 5);
    key[6] = ((hash[5] & 63) << 2) | (hash[6] >> 6);
    key[7] = ((hash[6] & 127) << 1);
}

static void
gen_md4_hash(const uint8_t *data, int data_len, uint8_t *result)
{
    /* result is 16 byte md4 hash */
    uint8_t md[MD4_DIGEST_LENGTH];

    md_full("MD4", data, data_len, md);
    memcpy(result, md, MD4_DIGEST_LENGTH);
}

static void
gen_hmac_md5(const uint8_t *data, int data_len, const uint8_t *key,
             uint8_t *result)
{
    hmac_ctx_t *hmac_ctx = hmac_ctx_new();

    hmac_ctx_init(hmac_ctx, key, "MD5");
    hmac_ctx_update(hmac_ctx, data, data_len);
    hmac_ctx_final(hmac_ctx, result);
    hmac_ctx_cleanup(hmac_ctx);
    hmac_ctx_free(hmac_ctx);
}

static void
gen_timestamp(uint8_t *timestamp)
{
    /* Copies 8 bytes long timestamp into "timestamp" buffer.
     * Timestamp is Little-endian, 64-bit signed value representing the
     * number of tenths of a microsecond since January 1, 1601.
     */

    UINTEGER64 timestamp_ull;

    timestamp_ull = openvpn_time(NULL);
    timestamp_ull = (timestamp_ull + UINT64(11644473600)) * UINT64(10000000);

    /* store little endian value */
    timestamp[0] = timestamp_ull & UINT64(0xFF);
    timestamp[1] = (timestamp_ull  >> 8)  & UINT64(0xFF);
    timestamp[2] = (timestamp_ull  >> 16) & UINT64(0xFF);
    timestamp[3] = (timestamp_ull  >> 24) & UINT64(0xFF);
    timestamp[4] = (timestamp_ull  >> 32) & UINT64(0xFF);
    timestamp[5] = (timestamp_ull  >> 40) & UINT64(0xFF);
    timestamp[6] = (timestamp_ull  >> 48) & UINT64(0xFF);
    timestamp[7] = (timestamp_ull  >> 56) & UINT64(0xFF);
}

static void
gen_nonce(unsigned char *nonce)
{
    /* Generates 8 random bytes to be used as client nonce */
    int i;

    for (i = 0; i<8; i++)
    {
        nonce[i] = (unsigned char)get_random();
    }
}

static void
my_strupr(char *str)
{
    /* converts string to uppercase in place */

    while (*str)
    {
        *str = toupper(*str);
        str++;
    }
}

/**
 * This function expects a null-terminated string in src and will
 * copy it (including the terminating NUL byte),
 * alternating it with 0 to dst.
 *
 * This basically will transform a ASCII string into valid UTF-16.
 * Characters that are 8bit in src, will get the same treatment, resulting in
 * invalid or wrong unicode code points.
 *
 * @note the function will blindly assume that dst has double
 * the space of src.
 * @return  the length of the number of bytes written to dst
 */
static int
unicodize(char *dst, const char *src)
{
    /* not really unicode... */
    int i = 0;
    do
    {
        dst[i++] = *src;
        dst[i++] = 0;
    } while (*src++);

    return i;
}

static void
add_security_buffer(int sb_offset, void *data, int length,
                    unsigned char *msg_buf, int *msg_bufpos, size_t msg_bufsize)
{
    if (*msg_bufpos + length > msg_bufsize)
    {
        msg(M_WARN, "NTLM: security buffer too big for message buffer");
        return;
    }
    /* Adds security buffer data to a message and sets security buffer's
     * offset and length */
    msg_buf[sb_offset] = (unsigned char)length;
    msg_buf[sb_offset + 2] = msg_buf[sb_offset];
    msg_buf[sb_offset + 4] = (unsigned char)(*msg_bufpos & 0xff);
    msg_buf[sb_offset + 5] = (unsigned char)((*msg_bufpos >> 8) & 0xff);
    memcpy(&msg_buf[*msg_bufpos], data, msg_buf[sb_offset]);
    *msg_bufpos += length;
}

const char *
ntlm_phase_1(const struct http_proxy_info *p, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(96, gc);
    /* try a minimal NTLM handshake
     *
     * http://davenport.sourceforge.net/ntlm.html
     *
     * This message contains only the NTLMSSP signature,
     * the NTLM message type,
     * and the minimal set of flags (Negotiate NTLM and Negotiate OEM).
     *
     */
    buf_printf(&out, "%s", "TlRMTVNTUAABAAAAAgIAAA==");
    return (BSTR(&out));
}

const char *
ntlm_phase_3(const struct http_proxy_info *p, const char *phase_2,
             struct gc_arena *gc)
{
    /* NTLM handshake
     *
     * http://davenport.sourceforge.net/ntlm.html
     *
     */

    char pwbuf[sizeof(p->up.password) * 2]; /* for unicode password */
    uint8_t phase3[464];

    uint8_t md4_hash[MD4_DIGEST_LENGTH + 5];
    uint8_t challenge[8], ntlm_response[24];
    int i, ret_val;

    uint8_t ntlmv2_response[256];
    char userdomain_u[256];     /* for uppercase unicode username and domain */
    char userdomain[128];       /* the same as previous but ascii */
    uint8_t ntlmv2_hash[MD5_DIGEST_LENGTH];
    uint8_t ntlmv2_hmacmd5[16];
    uint8_t *ntlmv2_blob = ntlmv2_response + 16;     /* inside ntlmv2_response, length: 128 */
    int ntlmv2_blob_size = 0;
    int phase3_bufpos = 0x40;     /* offset to next security buffer data to be added */
    size_t len;

    char domain[128];
    char username[128];
    char *separator;

    bool ntlmv2_enabled = (p->auth_method == HTTP_AUTH_NTLM2);

    ASSERT(strlen(p->up.username) > 0);
    ASSERT(strlen(p->up.password) > 0);

    /* username parsing */
    separator = strchr(p->up.username, '\\');
    if (separator == NULL)
    {
        strncpy(username, p->up.username, sizeof(username)-1);
        username[sizeof(username)-1] = 0;
        domain[0] = 0;
    }
    else
    {
        strncpy(username, separator+1, sizeof(username)-1);
        username[sizeof(username)-1] = 0;
        len = separator - p->up.username;
        if (len > sizeof(domain) - 1)
        {
            len = sizeof(domain) - 1;
        }
        strncpy(domain, p->up.username,  len);
        domain[len] = 0;
    }


    /* fill 1st 16 bytes with md4 hash, disregard terminating null */
    int unicode_len = unicodize(pwbuf, p->up.password) - 2;
    gen_md4_hash((uint8_t *)pwbuf, unicode_len, md4_hash);

    /* pad to 21 bytes */
    memset(md4_hash + MD4_DIGEST_LENGTH, 0, 5);

    /* If the decoded challenge is shorter than required by the protocol,
     * the missing bytes will be NULL, as buf2 is known to be zeroed
     * when this decode happens.
     */
    uint8_t buf2[512]; /* decoded reply from proxy */
    CLEAR(buf2);
    ret_val = openvpn_base64_decode(phase_2, buf2, -1);
    if (ret_val < 0)
    {
        msg(M_WARN, "NTLM: base64 decoding of phase 2 response failed");
        return NULL;
    }

    /* extract the challenge from bytes 24-31 */
    for (i = 0; i<8; i++)
    {
        challenge[i] = buf2[i+24];
    }

    if (ntlmv2_enabled)      /* Generate NTLMv2 response */
    {
        int tib_len;

        /* NTLMv2 hash */
        strcpy(userdomain, username);
        my_strupr(userdomain);
        if (strlen(username) + strlen(domain) < sizeof(userdomain))
        {
            strcat(userdomain, domain);
        }
        else
        {
            msg(M_WARN, "NTLM: Username or domain too long");
        }
        unicodize(userdomain_u, userdomain);
        gen_hmac_md5((uint8_t *)userdomain_u, 2 * strlen(userdomain), md4_hash,
                     ntlmv2_hash);

        /* NTLMv2 Blob */
        memset(ntlmv2_blob, 0, 128);                        /* Clear blob buffer */
        ntlmv2_blob[0x00] = 1;                              /* Signature */
        ntlmv2_blob[0x01] = 1;                              /* Signature */
        ntlmv2_blob[0x04] = 0;                              /* Reserved */
        gen_timestamp(&ntlmv2_blob[0x08]);                  /* 64-bit Timestamp */
        gen_nonce(&ntlmv2_blob[0x10]);                      /* 64-bit Client Nonce */
        ntlmv2_blob[0x18] = 0;                              /* Unknown, zero should work */

        /* Add target information block to the blob */

        /* Check for Target Information block */
        /* The NTLM spec instructs to interpret these 4 consecutive bytes as a
         * 32bit long integer. However, no endianness is specified.
         * The code here and that found in other NTLM implementations point
         * towards the assumption that the byte order on the wire has to
         * match the order on the sending and receiving hosts. Probably NTLM has
         * been thought to be always running on x86_64/i386 machine thus
         * implying Little-Endian everywhere.
         *
         * This said, in case of future changes, we should keep in mind that the
         * byte order on the wire for the NTLM header is LE.
         */
        const size_t hoff = 0x14;
        unsigned long flags = buf2[hoff] | (buf2[hoff + 1] << 8)
                              |(buf2[hoff + 2] << 16) | (buf2[hoff + 3] << 24);
        if ((flags & 0x00800000) == 0x00800000)
        {
            tib_len = buf2[0x28];            /* Get Target Information block size */
            if (tib_len + 0x1c + 16 > sizeof(ntlmv2_response))
            {
                msg(M_WARN, "NTLM: target information buffer too long for response (len=%d)", tib_len);
                return NULL;
            }

            {
                uint8_t *tib_ptr;
                uint8_t tib_pos = buf2[0x2c];
                if (tib_pos + tib_len > sizeof(buf2))
                {
                    msg(M_ERR, "NTLM: phase 2 response from server too long (need %d bytes at offset %u)", tib_len, tib_pos);
                    return NULL;
                }
                /* Get Target Information block pointer */
                tib_ptr = buf2 + tib_pos;
                /* Copy Target Information block into the blob */
                memcpy(&ntlmv2_blob[0x1c], tib_ptr, tib_len);
            }
        }
        else
        {
            tib_len = 0;
        }

        /* Unknown, zero works */
        ntlmv2_blob[0x1c + tib_len] = 0;

        /* Get blob length */
        ntlmv2_blob_size = 0x20 + tib_len;

        /* Add challenge from message 2 */
        memcpy(&ntlmv2_response[8], challenge, 8);

        /* hmac-md5 */
        gen_hmac_md5(&ntlmv2_response[8], ntlmv2_blob_size + 8, ntlmv2_hash,
                     ntlmv2_hmacmd5);

        /* Add hmac-md5 result to the blob.
         * Note: This overwrites challenge previously written at
         * ntlmv2_response[8..15] */
        memcpy(ntlmv2_response, ntlmv2_hmacmd5, MD5_DIGEST_LENGTH);
    }
    else /* Generate NTLM response */
    {
        unsigned char key1[DES_KEY_LENGTH], key2[DES_KEY_LENGTH];
        unsigned char key3[DES_KEY_LENGTH];

        create_des_keys(md4_hash, key1);
        cipher_des_encrypt_ecb(key1, challenge, ntlm_response);

        create_des_keys(&md4_hash[DES_KEY_LENGTH - 1], key2);
        cipher_des_encrypt_ecb(key2, challenge, &ntlm_response[DES_KEY_LENGTH]);

        create_des_keys(&md4_hash[2 * (DES_KEY_LENGTH - 1)], key3);
        cipher_des_encrypt_ecb(key3, challenge,
                               &ntlm_response[DES_KEY_LENGTH * 2]);
    }


    memset(phase3, 0, sizeof(phase3));       /* clear reply */

    strcpy((char *)phase3, "NTLMSSP\0");      /* signature */
    phase3[8] = 3;     /* type 3 */

    if (ntlmv2_enabled)      /* NTLMv2 response */
    {
        add_security_buffer(0x14, ntlmv2_response, ntlmv2_blob_size + 16,
                            phase3, &phase3_bufpos, sizeof(phase3));
    }
    else       /* NTLM response */
    {
        add_security_buffer(0x14, ntlm_response, 24, phase3, &phase3_bufpos, sizeof(phase3));
    }

    /* username in ascii */
    add_security_buffer(0x24, username, strlen(username), phase3,
                        &phase3_bufpos, sizeof(phase3));

    /* Set domain. If <domain> is empty, default domain will be used
     * (i.e. proxy's domain) */
    add_security_buffer(0x1c, domain, strlen(domain), phase3, &phase3_bufpos, sizeof(phase3));

    /* other security buffers will be empty */
    phase3[0x10] = phase3_bufpos;     /* lm not used */
    phase3[0x30] = phase3_bufpos;     /* no workstation name supplied */
    phase3[0x38] = phase3_bufpos;     /* no session key */

    /* flags */
    phase3[0x3c] = 0x02; /* negotiate oem */
    phase3[0x3d] = 0x02; /* negotiate ntlm */

    return ((const char *)make_base64_string2((unsigned char *)phase3,
                                              phase3_bufpos, gc));
}
#endif /* if NTLM */
