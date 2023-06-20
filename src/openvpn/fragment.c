/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2023 OpenVPN Inc <sales@openvpn.net>
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

#ifdef ENABLE_FRAGMENT

#include "crypto.h"
#include "misc.h"
#include "fragment.h"
#include "integer.h"
#include "memdbg.h"

#define FRAG_ERR(s) { errmsg = s; goto error; }

static void
fragment_list_buf_init(struct fragment_list *list, const struct frame *frame)
{
    int i;
    for (i = 0; i < N_FRAG_BUF; ++i)
    {
        list->fragments[i].buf = alloc_buf(BUF_SIZE(frame));
    }
}

static void
fragment_list_buf_free(struct fragment_list *list)
{
    int i;
    for (i = 0; i < N_FRAG_BUF; ++i)
    {
        free_buf(&list->fragments[i].buf);
    }
}

/*
 * Given a sequence ID number, get a fragment buffer.  Use a sliding window,
 * similar to packet_id code.
 */
static struct fragment *
fragment_list_get_buf(struct fragment_list *list, int seq_id)
{
    int diff;
    if (abs(diff = modulo_subtract(seq_id, list->seq_id, N_SEQ_ID)) >= N_FRAG_BUF)
    {
        int i;
        for (i = 0; i < N_FRAG_BUF; ++i)
        {
            list->fragments[i].defined = false;
        }
        list->index = 0;
        list->seq_id = seq_id;
        diff = 0;
    }
    while (diff > 0)
    {
        list->fragments[list->index = modulo_add(list->index, 1, N_FRAG_BUF)].defined = false;
        list->seq_id = modulo_add(list->seq_id, 1, N_SEQ_ID);
        --diff;
    }
    return &list->fragments[modulo_add(list->index, diff, N_FRAG_BUF)];
}

struct fragment_master *
fragment_init(struct frame *frame)
{
    struct fragment_master *ret;

    /* code that initializes other parts of
     * fragment_master assume an initial CLEAR */
    ALLOC_OBJ_CLEAR(ret, struct fragment_master);

    /*
     * Outgoing sequence ID is randomized to reduce
     * the probability of sequence number collisions
     * when openvpn sessions are restarted.  This is
     * not done out of any need for security, as all
     * fragmentation control information resides
     * inside of the encrypted/authenticated envelope.
     */
    ret->outgoing_seq_id = (int)get_random() & (N_SEQ_ID - 1);

    event_timeout_init(&ret->wakeup, FRAG_WAKEUP_INTERVAL, now);

    return ret;
}

void
fragment_free(struct fragment_master *f)
{
    fragment_list_buf_free(&f->incoming);
    free_buf(&f->outgoing);
    free_buf(&f->outgoing_return);
    free(f);
}

void
fragment_frame_init(struct fragment_master *f, const struct frame *frame)
{
    fragment_list_buf_init(&f->incoming, frame);
    f->outgoing = alloc_buf(BUF_SIZE(frame));
    f->outgoing_return = alloc_buf(BUF_SIZE(frame));
}

/*
 * Accept an incoming datagram (which may be a fragment) from remote.
 * If the datagram is whole (i.e not a fragment), pass through.
 * If the datagram is a fragment, join with other fragments received so far.
 * If a fragment fully completes the datagram, return the datagram.
 */
void
fragment_incoming(struct fragment_master *f, struct buffer *buf,
                  const struct frame *frame)
{
    const char *errmsg = NULL;
    fragment_header_type flags = 0;
    int frag_type = 0;

    if (buf->len > 0)
    {
        /* get flags from packet head */
        if (!buf_read(buf, &flags, sizeof(flags)))
        {
            FRAG_ERR("flags not found in packet");
        }
        flags = ntoh_fragment_header_type(flags);

        /* get fragment type from flags */
        frag_type = ((flags >> FRAG_TYPE_SHIFT) & FRAG_TYPE_MASK);

#if 0
        /*
         * If you want to extract FRAG_EXTRA_MASK/FRAG_EXTRA_SHIFT bits,
         * do it here.
         */
        if (frag_type == FRAG_WHOLE || frag_type == FRAG_YES_NOTLAST)
        {
        }
#endif

        /* handle the fragment type */
        if (frag_type == FRAG_WHOLE)
        {
            dmsg(D_FRAG_DEBUG,
                 "FRAG_IN buf->len=%d type=FRAG_WHOLE flags="
                 fragment_header_format,
                 buf->len,
                 flags);

            if (flags & (FRAG_SEQ_ID_MASK | FRAG_ID_MASK))
            {
                FRAG_ERR("spurious FRAG_WHOLE flags");
            }
        }
        else if (frag_type == FRAG_YES_NOTLAST || frag_type == FRAG_YES_LAST)
        {
            const int seq_id = ((flags >> FRAG_SEQ_ID_SHIFT) & FRAG_SEQ_ID_MASK);
            const int n = ((flags >> FRAG_ID_SHIFT) & FRAG_ID_MASK);
            const int size = ((frag_type == FRAG_YES_LAST)
                              ? (int)(((flags >> FRAG_SIZE_SHIFT) & FRAG_SIZE_MASK) << FRAG_SIZE_ROUND_SHIFT)
                              : buf->len);

            /* get the appropriate fragment buffer based on received seq_id */
            struct fragment *frag = fragment_list_get_buf(&f->incoming, seq_id);

            dmsg(D_FRAG_DEBUG,
                 "FRAG_IN len=%d type=%d seq_id=%d frag_id=%d size=%d flags="
                 fragment_header_format,
                 buf->len,
                 frag_type,
                 seq_id,
                 n,
                 size,
                 flags);

            /* make sure that size is an even multiple of 1<<FRAG_SIZE_ROUND_SHIFT */
            if (size & FRAG_SIZE_ROUND_MASK)
            {
                FRAG_ERR("bad fragment size");
            }

            /* is this the first fragment for our sequence number? */
            if (!frag->defined || frag->max_frag_size != size)
            {
                frag->defined = true;
                frag->max_frag_size = size;
                frag->map = 0;
                ASSERT(buf_init(&frag->buf, frame->buf.headroom));
            }

            /* copy the data to fragment buffer */
            if (!buf_copy_range(&frag->buf, n * size, buf, 0, buf->len))
            {
                FRAG_ERR("fragment buffer overflow");
            }

            /* set elements in bit array to reflect which fragments have been received */
            frag->map |= (((frag_type == FRAG_YES_LAST) ? FRAG_MAP_MASK : 1) << n);

            /* update timestamp on partially built datagram */
            frag->timestamp = now;

            /* received full datagram? */
            if ((frag->map & FRAG_MAP_MASK) == FRAG_MAP_MASK)
            {
                frag->defined = false;
                *buf = frag->buf;
            }
            else
            {
                buf->len = 0;
            }
        }
        else if (frag_type == FRAG_TEST)
        {
            FRAG_ERR("FRAG_TEST not implemented");
        }
        else
        {
            FRAG_ERR("unknown fragment type");
        }
    }

    return;

error:
    if (errmsg)
    {
        msg(D_FRAG_ERRORS, "FRAG_IN error flags=" fragment_header_format ": %s", flags, errmsg);
    }
    buf->len = 0;
    return;
}

/* pack fragment parms into a uint32_t and prepend to buffer */
static void
fragment_prepend_flags(struct buffer *buf,
                       int type,
                       int seq_id,
                       int frag_id,
                       int frag_size)
{
    fragment_header_type flags = ((type & FRAG_TYPE_MASK) << FRAG_TYPE_SHIFT)
                                 | ((seq_id & FRAG_SEQ_ID_MASK) << FRAG_SEQ_ID_SHIFT)
                                 | ((frag_id & FRAG_ID_MASK) << FRAG_ID_SHIFT);

    if (type == FRAG_WHOLE || type == FRAG_YES_NOTLAST)
    {
        /*
         * If you want to set FRAG_EXTRA_MASK/FRAG_EXTRA_SHIFT bits,
         * do it here.
         */
        dmsg(D_FRAG_DEBUG,
             "FRAG_OUT len=%d type=%d seq_id=%d frag_id=%d frag_size=%d flags="
             fragment_header_format,
             buf->len, type, seq_id, frag_id, frag_size, flags);
    }
    else
    {
        flags |= (((frag_size >> FRAG_SIZE_ROUND_SHIFT) & FRAG_SIZE_MASK) << FRAG_SIZE_SHIFT);

        dmsg(D_FRAG_DEBUG,
             "FRAG_OUT len=%d type=%d seq_id=%d frag_id=%d frag_size=%d flags="
             fragment_header_format,
             buf->len, type, seq_id, frag_id, frag_size, flags);
    }

    flags = hton_fragment_header_type(flags);
    ASSERT(buf_write_prepend(buf, &flags, sizeof(flags)));
}

/*
 * Without changing the number of fragments, return a possibly smaller
 * max fragment size that will allow for the last fragment to be of
 * similar size as previous fragments.
 */
static inline int
optimal_fragment_size(int len, int max_frag_size)
{
    const int mfs_aligned = (max_frag_size & ~FRAG_SIZE_ROUND_MASK);
    const int div = len / mfs_aligned;
    const int mod = len % mfs_aligned;

    if (div > 0 && mod > 0 && mod < mfs_aligned * 3 / 4)
    {
        return min_int(mfs_aligned, (max_frag_size - ((max_frag_size - mod) / (div + 1))
                                     + FRAG_SIZE_ROUND_MASK) & ~FRAG_SIZE_ROUND_MASK);
    }
    else
    {
        return mfs_aligned;
    }
}

/* process an outgoing datagram, possibly breaking it up into fragments */
void
fragment_outgoing(struct fragment_master *f, struct buffer *buf,
                  const struct frame *frame)
{
    const char *errmsg = NULL;
    if (buf->len > 0)
    {
        /* The outgoing buffer should be empty so we can put new data in it */
        if (f->outgoing.len)
        {
            msg(D_FRAG_ERRORS, "FRAG: outgoing buffer is not empty, len=[%d,%d]",
                buf->len, f->outgoing.len);
        }
        if (buf->len > frame->max_fragment_size) /* should we fragment? */
        {
            /*
             * Send the datagram as a series of 2 or more fragments.
             */
            f->outgoing_frag_size = optimal_fragment_size(buf->len, frame->max_fragment_size);
            if (buf->len > f->outgoing_frag_size * MAX_FRAGS)
            {
                FRAG_ERR("too many fragments would be required to send datagram");
            }
            ASSERT(buf_init(&f->outgoing, frame->buf.headroom));
            ASSERT(buf_copy(&f->outgoing, buf));
            f->outgoing_seq_id = modulo_add(f->outgoing_seq_id, 1, N_SEQ_ID);
            f->outgoing_frag_id = 0;
            buf->len = 0;
            ASSERT(fragment_ready_to_send(f, buf, frame));
        }
        else
        {
            /*
             * Send the datagram whole.
             */
            fragment_prepend_flags(buf,
                                   FRAG_WHOLE,
                                   0,
                                   0,
                                   0);
        }
    }
    return;

error:
    if (errmsg)
    {
        msg(D_FRAG_ERRORS, "FRAG_OUT error, len=%d frag_size=%d MAX_FRAGS=%d: %s",
            buf->len, f->outgoing_frag_size, MAX_FRAGS, errmsg);
    }
    buf->len = 0;
    return;
}

/* return true (and set buf) if we have an outgoing fragment which is ready to send */
bool
fragment_ready_to_send(struct fragment_master *f, struct buffer *buf,
                       const struct frame *frame)
{
    if (fragment_outgoing_defined(f))
    {
        /* get fragment size, and determine if it is the last fragment */
        int size = f->outgoing_frag_size;
        int last = false;
        if (f->outgoing.len <= size)
        {
            size = f->outgoing.len;
            last = true;
        }

        /* initialize return buffer */
        *buf = f->outgoing_return;
        ASSERT(buf_init(buf, frame->buf.headroom));
        ASSERT(buf_copy_n(buf, &f->outgoing, size));

        /* fragment flags differ based on whether or not we are sending the last fragment */
        fragment_prepend_flags(buf,
                               last ? FRAG_YES_LAST : FRAG_YES_NOTLAST,
                               f->outgoing_seq_id,
                               f->outgoing_frag_id++,
                               f->outgoing_frag_size);

        ASSERT(!last || !f->outgoing.len); /* outgoing buffer length should be zero after last fragment sent */

        return true;
    }
    else
    {
        return false;
    }
}

static void
fragment_ttl_reap(struct fragment_master *f)
{
    int i;
    for (i = 0; i < N_FRAG_BUF; ++i)
    {
        struct fragment *frag = &f->incoming.fragments[i];
        if (frag->defined && frag->timestamp + FRAG_TTL_SEC <= now)
        {
            msg(D_FRAG_ERRORS, "FRAG TTL expired i=%d", i);
            frag->defined = false;
        }
    }
}

/* called every FRAG_WAKEUP_INTERVAL seconds */
void
fragment_wakeup(struct fragment_master *f, struct frame *frame)
{
    /* delete fragments with expired TTLs */
    fragment_ttl_reap(f);
}
#endif /* ifdef ENABLE_FRAGMENT */
