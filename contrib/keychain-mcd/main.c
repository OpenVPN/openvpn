/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2015 Vasily Kulikov <segoon@openwall.com>
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


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <err.h>
#include <netdb.h>

#include <Security/Security.h>
#include <CoreServices/CoreServices.h>

#include "cert_data.h"
#include "crypto_osx.h"
#include "../../src/openvpn/base64.h"


SecIdentityRef
template_to_identity(const char *template)
{
    SecIdentityRef identity;
    CertDataRef pCertDataTemplate = createCertDataFromString(template);
    if (pCertDataTemplate == NULL)
    {
        errx(1, "Bad certificate template");
    }
    identity = findIdentity(pCertDataTemplate);
    if (identity == NULL)
    {
        errx(1, "No such identify");
    }
    fprintf(stderr, "Identity found\n");
    destroyCertData(pCertDataTemplate);
    return identity;
}

int
connect_to_management_server(const char *ip, const char *port)
{
    int fd;
    struct sockaddr_un addr_un;
    struct sockaddr *addr;
    size_t addr_len;

    if (strcmp(port, "unix") == 0)
    {
        addr = (struct sockaddr *)&addr_un;
        addr_len = sizeof(addr_un);

        addr_un.sun_family = AF_UNIX;
        strncpy(addr_un.sun_path, ip, sizeof(addr_un.sun_path));
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
    }
    else
    {
        int rv;
        struct addrinfo *result;
        struct addrinfo hints;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        rv = getaddrinfo(ip, port, &hints, &result);
        if (rv < 0)
        {
            errx(1, "getaddrinfo: %s", gai_strerror(rv));
        }
        if (result == NULL)
        {
            errx(1, "getaddrinfo returned 0 addressed");
        }

        /* Use the first found address */
        fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        addr = result->ai_addr;
        addr_len = result->ai_addrlen;
    }
    if (fd < 0)
    {
        err(1, "socket");
    }

    if (connect(fd, addr, addr_len) < 0)
    {
        err(1, "connect");
    }

    return fd;
}

int
is_prefix(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

void
handle_rsasign(FILE *man_file, SecIdentityRef identity, const char *input)
{
    const char *input_b64 = strchr(input, ':') + 1;
    char *input_binary;
    int input_len;
    char *output_binary;
    size_t output_len;
    char *output_b64;

    input_len = strlen(input_b64)*8/6 + 4;
    input_binary = malloc(input_len);
    input_len = openvpn_base64_decode(input_b64, input_binary, input_len);
    if (input_len < 0)
    {
        errx(1, "openvpn_base64_decode: overflow");
    }

    output_len = 1024;
    output_binary = malloc(output_len);
    signData(identity, (const uint8_t *)input_binary, input_len, (uint8_t *)output_binary, &output_len);
    if (output_len == 0)
    {
        errx(1, "handle_rsasign: failed to sign data");
    }

    openvpn_base64_encode(output_binary, output_len, &output_b64);
    fprintf(man_file, "rsa-sig\n%s\nEND\n", output_b64);
    free(output_b64);
    free(input_binary);
    free(output_binary);

    fprintf(stderr, "Handled RSA_SIGN command\n");
}

void
handle_needcertificate(FILE *man_file, SecIdentityRef identity)
{
    OSStatus status;
    SecCertificateRef certificate = NULL;
    CFDataRef data;
    const unsigned char *cert;
    size_t cert_len;
    char *result_b64, *tmp_b64;

    status = SecIdentityCopyCertificate(identity, &certificate);
    if (status != noErr)
    {
        const char *msg = GetMacOSStatusErrorString(status);
        err(1, "SecIdentityCopyCertificate() failed: %s", msg);
    }

    data = SecCertificateCopyData(certificate);
    if (data == NULL)
    {
        err(1, "SecCertificateCopyData() returned NULL");
    }

    cert = CFDataGetBytePtr(data);
    cert_len = CFDataGetLength(data);

    openvpn_base64_encode(cert, cert_len, &result_b64);
#if 0
    fprintf(stderr, "certificate %s\n", result_b64);
#endif

    fprintf(man_file, "certificate\n");
    fprintf(man_file, "-----BEGIN CERTIFICATE-----\n");
    tmp_b64 = result_b64;
    while (strlen(tmp_b64) > 64) {
        fprintf(man_file, "%.64s\n", tmp_b64);
        tmp_b64 += 64;
    }
    if (*tmp_b64)
    {
        fprintf(man_file, "%s\n", tmp_b64);
    }
    fprintf(man_file, "-----END CERTIFICATE-----\n");
    fprintf(man_file, "END\n");

    free(result_b64);
    CFRelease(data);
    CFRelease(certificate);

    fprintf(stderr, "Handled NEED 'cert' command\n");
}

void
management_loop(SecIdentityRef identity, int man_fd, const char *password)
{
    char *buffer = NULL;
    size_t buffer_len = 0;
    FILE *man = fdopen(man_fd, "w+");
    if (man == 0)
    {
        err(1, "fdopen");
    }

    if (password)
    {
        fprintf(man, "%s\n", password);
    }

    while (1) {
        if (getline(&buffer, &buffer_len, man) < 0)
        {
            err(1, "getline");
        }
#if 0
        fprintf(stderr, "M: %s", buffer);
#endif

        if (is_prefix(buffer, ">RSA_SIGN:"))
        {
            handle_rsasign(man, identity, buffer);
        }
        if (is_prefix(buffer, ">NEED-CERTIFICATE"))
        {
            if (!identity)
            {
                const char prefix[] = ">NEED-CERTIFICATE:macosx-keychain:";
                if (!is_prefix(buffer, prefix))
                {
                    errx(1, "No identity template is passed via command line and " \
                         "NEED-CERTIFICATE management interface command " \
                         "misses 'macosx-keychain' prefix.");
                }
                identity = template_to_identity(buffer+strlen(prefix));
            }
            handle_needcertificate(man, identity);
        }
        if (is_prefix(buffer, ">FATAL"))
        {
            fprintf(stderr, "Fatal message from OpenVPN: %s\n", buffer+7);
        }
        if (is_prefix(buffer, ">INFO"))
        {
            fprintf(stderr, "INFO message from OpenVPN: %s\n", buffer+6);
        }
    }
}

char *
read_password(const char *fname)
{
    char *password = NULL;
    FILE *pwf = fopen(fname, "r");
    size_t n = 0;

    if (pwf == NULL)
    {
        errx(1, "fopen(%s) failed", fname);
    }
    if (getline(&password, &n, pwf) < 0)
    {
        err(1, "getline");
    }
    fclose(pwf);
    return password;
}

int
main(int argc, char *argv[])
{
    if (argc < 4)
    {
        err(1, "usage: %s <identity_template> <management_ip> <management_port> [<pw-file>]", argv[0]);
    }

    char *identity_template = argv[1];
    char *s_ip = argv[2];
    char *s_port = argv[3];
    char *password = NULL;
    int man_fd;

    if (argc > 4)
    {
        char *s_pw_file = argv[4];
        password = read_password(s_pw_file);
    }

    SecIdentityRef identity = NULL;
    if (strcmp(identity_template, "auto"))
    {
        identity = template_to_identity(identity_template);
    }
    man_fd = connect_to_management_server(s_ip, s_port);
    fprintf(stderr, "Successfully connected to openvpn\n");

    management_loop(identity, man_fd, password);
}
