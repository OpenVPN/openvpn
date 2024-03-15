/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
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

#include "ssl_util.h"

char *
extract_var_peer_info(const char *peer_info, const char *var,
                      struct gc_arena *gc)
{
    if (!peer_info)
    {
        return NULL;
    }

    const char *var_start = strstr(peer_info, var);
    if (!var_start)
    {
        /* variable not found in peer info */
        return NULL;
    }

    var_start += strlen(var);
    const char *var_end = strstr(var_start, "\n");
    if (!var_end)
    {
        /* var is at end of the peer_info list and no '\n' follows */
        var_end = var_start + strlen(var_start);
    }

    char *var_value = string_alloc(var_start, gc);
    /* NULL terminate the copy at the right position */
    var_value[var_end - var_start] = '\0';
    return var_value;
}

unsigned int
extract_iv_proto(const char *peer_info)
{
    const char *optstr = peer_info ? strstr(peer_info, "IV_PROTO=") : NULL;
    if (optstr)
    {
        int proto = 0;
        int r = sscanf(optstr, "IV_PROTO=%d", &proto);
        if (r == 1 && proto > 0)
        {
            return proto;
        }
    }
    return 0;
}

const char *
options_string_compat_lzo(const char *options, struct gc_arena *gc)
{
    /* Example string without and with comp-lzo, i.e. input/output of this function */
    /* w/o comp: 'V4,dev-type tun,link-mtu 1457,tun-mtu 1400,proto UDPv4,auth SHA1,keysize 128,key-method 2,tls-server' */
    /* comp-lzo: 'V4,dev-type tun,link-mtu 1458,tun-mtu 1400,proto UDPv4,comp-lzo,auth SHA1,keysize 128,key-method 2,tls-server' */

    /* Note: since this function is used only in a very limited scope it makes
     * assumptions how the string looks. Since we locally generated the string
     * we can make these assumptions */

    /* Check that the link-mtu string is in options */
    const char *tmp = strstr(options, ",link-mtu");
    if (!tmp)
    {
        return options;
    }

    /* Get old link_mtu size */
    int link_mtu;
    if (sscanf(tmp, ",link-mtu %d,", &link_mtu) != 1 || link_mtu < 100 || link_mtu > 9900)
    {
        return options;
    }

    /* 1 byte for the possibility of 999 to 1000 and 1 byte for the null
     * terminator */
    struct buffer buf = alloc_buf_gc(strlen(options) + strlen(",comp-lzo") + 2, gc);

    buf_write(&buf, options, (int)(tmp - options));

    /* Increase link-mtu by one for the comp-lzo opcode */
    buf_printf(&buf, ",link-mtu %d", link_mtu + 1);

    tmp += strlen(",link-mtu ") + (link_mtu < 1000 ? 3 : 4);

    buf_printf(&buf, "%s,comp-lzo", tmp);

    return BSTR(&buf);
}

/**
 * SSL/TLS Cipher suite name translation table
 */
static const tls_cipher_name_pair tls_cipher_name_translation_table[] = {
    {"ADH-SEED-SHA", "TLS-DH-anon-WITH-SEED-CBC-SHA"},
    {"AES128-GCM-SHA256", "TLS-RSA-WITH-AES-128-GCM-SHA256"},
    {"AES128-SHA256", "TLS-RSA-WITH-AES-128-CBC-SHA256"},
    {"AES128-SHA", "TLS-RSA-WITH-AES-128-CBC-SHA"},
    {"AES256-GCM-SHA384", "TLS-RSA-WITH-AES-256-GCM-SHA384"},
    {"AES256-SHA256", "TLS-RSA-WITH-AES-256-CBC-SHA256"},
    {"AES256-SHA", "TLS-RSA-WITH-AES-256-CBC-SHA"},
    {"CAMELLIA128-SHA256", "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256"},
    {"CAMELLIA128-SHA", "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA"},
    {"CAMELLIA256-SHA256", "TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256"},
    {"CAMELLIA256-SHA", "TLS-RSA-WITH-CAMELLIA-256-CBC-SHA"},
    {"DES-CBC3-SHA", "TLS-RSA-WITH-3DES-EDE-CBC-SHA"},
    {"DES-CBC-SHA", "TLS-RSA-WITH-DES-CBC-SHA"},
    {"DH-DSS-SEED-SHA", "TLS-DH-DSS-WITH-SEED-CBC-SHA"},
    {"DHE-DSS-AES128-GCM-SHA256", "TLS-DHE-DSS-WITH-AES-128-GCM-SHA256"},
    {"DHE-DSS-AES128-SHA256", "TLS-DHE-DSS-WITH-AES-128-CBC-SHA256"},
    {"DHE-DSS-AES128-SHA", "TLS-DHE-DSS-WITH-AES-128-CBC-SHA"},
    {"DHE-DSS-AES256-GCM-SHA384", "TLS-DHE-DSS-WITH-AES-256-GCM-SHA384"},
    {"DHE-DSS-AES256-SHA256", "TLS-DHE-DSS-WITH-AES-256-CBC-SHA256"},
    {"DHE-DSS-AES256-SHA", "TLS-DHE-DSS-WITH-AES-256-CBC-SHA"},
    {"DHE-DSS-CAMELLIA128-SHA256", "TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256"},
    {"DHE-DSS-CAMELLIA128-SHA", "TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA"},
    {"DHE-DSS-CAMELLIA256-SHA256", "TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256"},
    {"DHE-DSS-CAMELLIA256-SHA", "TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA"},
    {"DHE-DSS-SEED-SHA", "TLS-DHE-DSS-WITH-SEED-CBC-SHA"},
    {"DHE-RSA-AES128-GCM-SHA256", "TLS-DHE-RSA-WITH-AES-128-GCM-SHA256"},
    {"DHE-RSA-AES128-SHA256", "TLS-DHE-RSA-WITH-AES-128-CBC-SHA256"},
    {"DHE-RSA-AES128-SHA", "TLS-DHE-RSA-WITH-AES-128-CBC-SHA"},
    {"DHE-RSA-AES256-GCM-SHA384", "TLS-DHE-RSA-WITH-AES-256-GCM-SHA384"},
    {"DHE-RSA-AES256-SHA256", "TLS-DHE-RSA-WITH-AES-256-CBC-SHA256"},
    {"DHE-RSA-AES256-SHA", "TLS-DHE-RSA-WITH-AES-256-CBC-SHA"},
    {"DHE-RSA-CAMELLIA128-SHA256", "TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256"},
    {"DHE-RSA-CAMELLIA128-SHA", "TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA"},
    {"DHE-RSA-CAMELLIA256-SHA256", "TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256"},
    {"DHE-RSA-CAMELLIA256-SHA", "TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA"},
    {"DHE-RSA-CHACHA20-POLY1305", "TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256"},
    {"DHE-RSA-SEED-SHA", "TLS-DHE-RSA-WITH-SEED-CBC-SHA"},
    {"DH-RSA-SEED-SHA", "TLS-DH-RSA-WITH-SEED-CBC-SHA"},
    {"ECDH-ECDSA-AES128-GCM-SHA256", "TLS-ECDH-ECDSA-WITH-AES-128-GCM-SHA256"},
    {"ECDH-ECDSA-AES128-SHA256", "TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA256"},
    {"ECDH-ECDSA-AES128-SHA", "TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA"},
    {"ECDH-ECDSA-AES256-GCM-SHA384", "TLS-ECDH-ECDSA-WITH-AES-256-GCM-SHA384"},
    {"ECDH-ECDSA-AES256-SHA256", "TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA256"},
    {"ECDH-ECDSA-AES256-SHA384", "TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA384"},
    {"ECDH-ECDSA-AES256-SHA", "TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA"},
    {"ECDH-ECDSA-CAMELLIA128-SHA256", "TLS-ECDH-ECDSA-WITH-CAMELLIA-128-CBC-SHA256"},
    {"ECDH-ECDSA-CAMELLIA128-SHA", "TLS-ECDH-ECDSA-WITH-CAMELLIA-128-CBC-SHA"},
    {"ECDH-ECDSA-CAMELLIA256-SHA256", "TLS-ECDH-ECDSA-WITH-CAMELLIA-256-CBC-SHA256"},
    {"ECDH-ECDSA-CAMELLIA256-SHA", "TLS-ECDH-ECDSA-WITH-CAMELLIA-256-CBC-SHA"},
    {"ECDH-ECDSA-DES-CBC3-SHA", "TLS-ECDH-ECDSA-WITH-3DES-EDE-CBC-SHA"},
    {"ECDH-ECDSA-DES-CBC-SHA", "TLS-ECDH-ECDSA-WITH-DES-CBC-SHA"},
    {"ECDH-ECDSA-RC4-SHA", "TLS-ECDH-ECDSA-WITH-RC4-128-SHA"},
    {"ECDHE-ECDSA-AES128-GCM-SHA256", "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"},
    {"ECDHE-ECDSA-AES128-SHA256", "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256"},
    {"ECDHE-ECDSA-AES128-SHA384", "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA384"},
    {"ECDHE-ECDSA-AES128-SHA", "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA"},
    {"ECDHE-ECDSA-AES256-GCM-SHA384", "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"},
    {"ECDHE-ECDSA-AES256-SHA256", "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA256"},
    {"ECDHE-ECDSA-AES256-SHA384", "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384"},
    {"ECDHE-ECDSA-AES256-SHA", "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA"},
    {"ECDHE-ECDSA-CAMELLIA128-SHA256", "TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-CBC-SHA256"},
    {"ECDHE-ECDSA-CAMELLIA128-SHA", "TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-CBC-SHA"},
    {"ECDHE-ECDSA-CAMELLIA256-SHA256", "TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-CBC-SHA256"},
    {"ECDHE-ECDSA-CAMELLIA256-SHA", "TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-CBC-SHA"},
    {"ECDHE-ECDSA-CHACHA20-POLY1305", "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256"},
    {"ECDHE-ECDSA-DES-CBC3-SHA", "TLS-ECDHE-ECDSA-WITH-3DES-EDE-CBC-SHA"},
    {"ECDHE-ECDSA-DES-CBC-SHA", "TLS-ECDHE-ECDSA-WITH-DES-CBC-SHA"},
    {"ECDHE-ECDSA-RC4-SHA", "TLS-ECDHE-ECDSA-WITH-RC4-128-SHA"},
    {"ECDHE-RSA-AES128-GCM-SHA256", "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"},
    {"ECDHE-RSA-AES128-SHA256", "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256"},
    {"ECDHE-RSA-AES128-SHA384", "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA384"},
    {"ECDHE-RSA-AES128-SHA", "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA"},
    {"ECDHE-RSA-AES256-GCM-SHA384", "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"},
    {"ECDHE-RSA-AES256-SHA256", "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA256"},
    {"ECDHE-RSA-AES256-SHA384", "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384"},
    {"ECDHE-RSA-AES256-SHA", "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA"},
    {"ECDHE-RSA-CAMELLIA128-SHA256", "TLS-ECDHE-RSA-WITH-CAMELLIA-128-CBC-SHA256"},
    {"ECDHE-RSA-CAMELLIA128-SHA", "TLS-ECDHE-RSA-WITH-CAMELLIA-128-CBC-SHA"},
    {"ECDHE-RSA-CAMELLIA256-SHA256", "TLS-ECDHE-RSA-WITH-CAMELLIA-256-CBC-SHA256"},
    {"ECDHE-RSA-CAMELLIA256-SHA", "TLS-ECDHE-RSA-WITH-CAMELLIA-256-CBC-SHA"},
    {"ECDHE-RSA-CHACHA20-POLY1305", "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256"},
    {"ECDHE-RSA-DES-CBC3-SHA", "TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA"},
    {"ECDHE-RSA-DES-CBC-SHA", "TLS-ECDHE-RSA-WITH-DES-CBC-SHA"},
    {"ECDHE-RSA-RC4-SHA", "TLS-ECDHE-RSA-WITH-RC4-128-SHA"},
    {"ECDH-RSA-AES128-GCM-SHA256", "TLS-ECDH-RSA-WITH-AES-128-GCM-SHA256"},
    {"ECDH-RSA-AES128-SHA256", "TLS-ECDH-RSA-WITH-AES-128-CBC-SHA256"},
    {"ECDH-RSA-AES128-SHA384", "TLS-ECDH-RSA-WITH-AES-128-CBC-SHA384"},
    {"ECDH-RSA-AES128-SHA", "TLS-ECDH-RSA-WITH-AES-128-CBC-SHA"},
    {"ECDH-RSA-AES256-GCM-SHA384", "TLS-ECDH-RSA-WITH-AES-256-GCM-SHA384"},
    {"ECDH-RSA-AES256-SHA256", "TLS-ECDH-RSA-WITH-AES-256-CBC-SHA256"},
    {"ECDH-RSA-AES256-SHA384", "TLS-ECDH-RSA-WITH-AES-256-CBC-SHA384"},
    {"ECDH-RSA-AES256-SHA", "TLS-ECDH-RSA-WITH-AES-256-CBC-SHA"},
    {"ECDH-RSA-CAMELLIA128-SHA256", "TLS-ECDH-RSA-WITH-CAMELLIA-128-CBC-SHA256"},
    {"ECDH-RSA-CAMELLIA128-SHA", "TLS-ECDH-RSA-WITH-CAMELLIA-128-CBC-SHA"},
    {"ECDH-RSA-CAMELLIA256-SHA256", "TLS-ECDH-RSA-WITH-CAMELLIA-256-CBC-SHA256"},
    {"ECDH-RSA-CAMELLIA256-SHA", "TLS-ECDH-RSA-WITH-CAMELLIA-256-CBC-SHA"},
    {"ECDH-RSA-DES-CBC3-SHA", "TLS-ECDH-RSA-WITH-3DES-EDE-CBC-SHA"},
    {"ECDH-RSA-DES-CBC-SHA", "TLS-ECDH-RSA-WITH-DES-CBC-SHA"},
    {"ECDH-RSA-RC4-SHA", "TLS-ECDH-RSA-WITH-RC4-128-SHA"},
    {"EDH-DSS-DES-CBC3-SHA", "TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA"},
    {"EDH-DSS-DES-CBC-SHA", "TLS-DHE-DSS-WITH-DES-CBC-SHA"},
    {"EDH-RSA-DES-CBC3-SHA", "TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA"},
    {"EDH-RSA-DES-CBC-SHA", "TLS-DHE-RSA-WITH-DES-CBC-SHA"},
    {"EXP-DES-CBC-SHA", "TLS-RSA-EXPORT-WITH-DES40-CBC-SHA"},
    {"EXP-EDH-DSS-DES-CBC-SHA", "TLS-DH-DSS-EXPORT-WITH-DES40-CBC-SHA"},
    {"EXP-EDH-RSA-DES-CBC-SHA", "TLS-DH-RSA-EXPORT-WITH-DES40-CBC-SHA"},
    {"EXP-RC2-CBC-MD5", "TLS-RSA-EXPORT-WITH-RC2-CBC-40-MD5"},
    {"EXP-RC4-MD5", "TLS-RSA-EXPORT-WITH-RC4-40-MD5"},
    {"NULL-MD5", "TLS-RSA-WITH-NULL-MD5"},
    {"NULL-SHA256", "TLS-RSA-WITH-NULL-SHA256"},
    {"NULL-SHA", "TLS-RSA-WITH-NULL-SHA"},
    {"PSK-3DES-EDE-CBC-SHA", "TLS-PSK-WITH-3DES-EDE-CBC-SHA"},
    {"PSK-AES128-CBC-SHA", "TLS-PSK-WITH-AES-128-CBC-SHA"},
    {"PSK-AES256-CBC-SHA", "TLS-PSK-WITH-AES-256-CBC-SHA"},
    {"PSK-RC4-SHA", "TLS-PSK-WITH-RC4-128-SHA"},
    {"RC4-MD5", "TLS-RSA-WITH-RC4-128-MD5"},
    {"RC4-SHA", "TLS-RSA-WITH-RC4-128-SHA"},
    {"SEED-SHA", "TLS-RSA-WITH-SEED-CBC-SHA"},
    {"SRP-DSS-3DES-EDE-CBC-SHA", "TLS-SRP-SHA-DSS-WITH-3DES-EDE-CBC-SHA"},
    {"SRP-DSS-AES-128-CBC-SHA", "TLS-SRP-SHA-DSS-WITH-AES-128-CBC-SHA"},
    {"SRP-DSS-AES-256-CBC-SHA", "TLS-SRP-SHA-DSS-WITH-AES-256-CBC-SHA"},
    {"SRP-RSA-3DES-EDE-CBC-SHA", "TLS-SRP-SHA-RSA-WITH-3DES-EDE-CBC-SHA"},
    {"SRP-RSA-AES-128-CBC-SHA", "TLS-SRP-SHA-RSA-WITH-AES-128-CBC-SHA"},
    {"SRP-RSA-AES-256-CBC-SHA", "TLS-SRP-SHA-RSA-WITH-AES-256-CBC-SHA"},
#ifdef ENABLE_CRYPTO_OPENSSL
    /* OpenSSL-specific group names */
    {"DEFAULT", "DEFAULT"},
    {"ALL", "ALL"},
    {"HIGH", "HIGH"}, {"!HIGH", "!HIGH"},
    {"MEDIUM", "MEDIUM"}, {"!MEDIUM", "!MEDIUM"},
    {"LOW", "LOW"}, {"!LOW", "!LOW"},
    {"ECDH", "ECDH"}, {"!ECDH", "!ECDH"},
    {"ECDSA", "ECDSA"}, {"!ECDSA", "!ECDSA"},
    {"EDH", "EDH"}, {"!EDH", "!EDH"},
    {"EXP", "EXP"}, {"!EXP", "!EXP"},
    {"RSA", "RSA"}, {"!RSA", "!RSA"},
    {"kRSA", "kRSA"}, {"!kRSA", "!kRSA"},
    {"SRP", "SRP"}, {"!SRP", "!SRP"},
#endif
    {NULL, NULL}
};

const tls_cipher_name_pair *
tls_get_cipher_name_pair(const char *cipher_name, size_t len)
{
    const tls_cipher_name_pair *pair = tls_cipher_name_translation_table;

    while (pair->openssl_name != NULL)
    {
        if ((strlen(pair->openssl_name) == len && 0 == memcmp(cipher_name, pair->openssl_name, len))
            || (strlen(pair->iana_name) == len && 0 == memcmp(cipher_name, pair->iana_name, len)))
        {
            return pair;
        }
        pair++;
    }

    /* No entry found, return NULL */
    return NULL;
}

int
get_num_elements(const char *string, char delimiter)
{
    int string_len = strlen(string);

    ASSERT(0 != string_len);

    int element_count = 1;
    /* Get number of ciphers */
    for (int i = 0; i < string_len; i++)
    {
        if (string[i] == delimiter)
        {
            element_count++;
        }
    }

    return element_count;
}
