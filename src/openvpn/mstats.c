/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2021 OpenVPN Inc <sales@openvpn.net>
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

/*
 * Maintain usage stats in a memory-mapped file
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_MEMSTATS)

#include <sys/mman.h>

#include "error.h"
#include "misc.h"
#include "mstats.h"

#include "memdbg.h"

volatile struct mmap_stats *mmap_stats = NULL; /* GLOBAL */
static char mmap_fn[128];

void
mstats_open(const char *fn)
{
    void *data;
    ssize_t stat;
    int fd;
    struct mmap_stats ms;

    if (mmap_stats) /* already called? */
    {
        return;
    }

    /* verify that filename is not too long */
    if (strlen(fn) >= sizeof(mmap_fn))
    {
        msg(M_FATAL, "mstats_open: filename too long");
    }

    /* create file that will be memory mapped */
    fd = open(fn, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        msg(M_ERR, "mstats_open: cannot open: %s", fn);
        return;
    }

    /* set the file to the correct size to contain a
     * struct mmap_stats, and zero it */
    CLEAR(ms);
    ms.state = MSTATS_ACTIVE;
    stat = write(fd, &ms, sizeof(ms));
    if (stat != sizeof(ms))
    {
        msg(M_ERR, "mstats_open: write error: %s", fn);
        close(fd);
        return;
    }

    /* mmap the file */
    data = mmap(NULL, sizeof(struct mmap_stats), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (data == MAP_FAILED)
    {
        msg(M_ERR, "mstats_open: write error: %s", fn);
        close(fd);
        return;
    }

    /* close the fd (mmap now controls the file) */
    if (close(fd))
    {
        msg(M_ERR, "mstats_open: close error: %s", fn);
    }

    /* save filename so we can delete it later */
    strcpy(mmap_fn, fn);

    /* save a global pointer to memory-mapped region */
    mmap_stats = (struct mmap_stats *)data;

    msg(M_INFO, "memstats data will be written to %s", fn);
}

void
mstats_close(void)
{
    if (mmap_stats)
    {
        mmap_stats->state = MSTATS_EXPIRED;
        if (munmap((void *)mmap_stats, sizeof(struct mmap_stats)))
        {
            msg(M_WARN | M_ERRNO, "mstats_close: munmap error");
        }
        platform_unlink(mmap_fn);
        mmap_stats = NULL;
    }
}

#endif /* if defined(ENABLE_MEMSTATS) */
