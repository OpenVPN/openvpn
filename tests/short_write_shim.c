/*
 * short_write_shim.c -- LD_PRELOAD shim that injects short writes into send()
 *                       Intercepts TCP data-channel packets only, letting the
 *                       TLS handshake complete before corrupting the stream.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/socket.h>

/* Opcodes from ssl_pkt.h -- high 5 bits of the opcode byte */
#define P_OPCODE_SHIFT  3
#define P_DATA_V1       6
#define P_DATA_V2       9

static ssize_t (*real_send)(int, const void *, size_t, int);

static void __attribute__((constructor))
shim_init(void)
{
    real_send = dlsym(RTLD_NEXT, "send");
}

ssize_t
send(int fd, const void *buf, size_t len, int flags)
{
    /*
     * Over TCP, OpenVPN prepends a 2-byte big-endian length header to every
     * packet. Byte 2 (index 2) carries the opcode in its high 5 bits.
     * We need at least 3 bytes to inspect the opcode.
     */
    if (len >= 3)
    {
        const unsigned char *p = (const unsigned char *)buf;
        int opcode = (p[2] >> P_OPCODE_SHIFT);

        if (opcode == P_DATA_V1 || opcode == P_DATA_V2)
        {
            return real_send(fd, buf, len / 2, flags);
        }
    }

    return real_send(fd, buf, len, flags);
}
