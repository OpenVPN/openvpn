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

/*
 * These routines implement a reliability layer on top of UDP,
 * so that SSL/TLS can be run over UDP.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "buffer.h"
#include "error.h"
#include "common.h"
#include "reliable.h"

#include "memdbg.h"

/* calculates test - base while allowing for base or test wraparound. test is
 * assumed to be higher than base */
static inline packet_id_type
subtract_pid(const packet_id_type test, const packet_id_type base)
{
    return test - base;
}

/*
 * verify that test - base < extent while allowing for base or test wraparound
 */
static inline bool
reliable_pid_in_range1(const packet_id_type test,
                       const packet_id_type base,
                       const unsigned int extent)
{
    return subtract_pid(test, base) < extent;
}

/*
 * verify that test < base + extent while allowing for base or test wraparound
 */
static inline bool
reliable_pid_in_range2(const packet_id_type test,
                       const packet_id_type base,
                       const unsigned int extent)
{
    if (base + extent >= base)
    {
        if (test < base + extent)
        {
            return true;
        }
    }
    else
    {
        if ((test+0x80000000u) < (base+0x80000000u) + extent)
        {
            return true;
        }
    }

    return false;
}

/*
 * verify that p1 < p2  while allowing for p1 or p2 wraparound
 */
static inline bool
reliable_pid_min(const packet_id_type p1,
                 const packet_id_type p2)
{
    return !reliable_pid_in_range1(p1, p2, 0x80000000u);
}

/* check if a particular packet_id is present in ack */
static inline bool
reliable_ack_packet_id_present(struct reliable_ack *ack, packet_id_type pid)
{
    int i;
    for (i = 0; i < ack->len; ++i)
    {
        if (ack->packet_id[i] == pid)
        {
            return true;
        }
    }
    return false;
}

/* get a packet_id from buf */
bool
reliable_ack_read_packet_id(struct buffer *buf, packet_id_type *pid)
{
    packet_id_type net_pid;

    if (buf_read(buf, &net_pid, sizeof(net_pid)))
    {
        *pid = ntohpid(net_pid);
        dmsg(D_REL_DEBUG, "ACK read ID " packet_id_format " (buf->len=%d)",
             (packet_id_print_type)*pid, buf->len);
        return true;
    }

    dmsg(D_REL_LOW, "ACK read ID FAILED (buf->len=%d)", buf->len);
    return false;
}

/* acknowledge a packet_id by adding it to a struct reliable_ack */
bool
reliable_ack_acknowledge_packet_id(struct reliable_ack *ack, packet_id_type pid)
{
    if (!reliable_ack_packet_id_present(ack, pid) && ack->len < RELIABLE_ACK_SIZE)
    {
        ack->packet_id[ack->len++] = pid;
        dmsg(D_REL_DEBUG, "ACK acknowledge ID " packet_id_format " (ack->len=%d)",
             (packet_id_print_type)pid, ack->len);
        return true;
    }

    dmsg(D_REL_LOW, "ACK acknowledge ID " packet_id_format " FAILED (ack->len=%d)",
         (packet_id_print_type)pid, ack->len);
    return false;
}


bool
reliable_ack_read(struct reliable_ack *ack,
                  struct buffer *buf, const struct session_id *sid)
{
    struct session_id session_id_remote;

    if (!reliable_ack_parse(buf, ack, &session_id_remote))
    {
        return false;
    }

    if (ack->len >= 1 && (!session_id_defined(&session_id_remote)
                          || !session_id_equal(&session_id_remote, sid)))
    {
        struct gc_arena gc = gc_new();
        dmsg(D_REL_LOW,
             "ACK read BAD SESSION-ID FROM REMOTE, local=%s, remote=%s",
             session_id_print(sid, &gc), session_id_print(&session_id_remote, &gc));
        gc_free(&gc);
        return false;
    }
    return true;
}

bool
reliable_ack_parse(struct buffer *buf, struct reliable_ack *ack,
                   struct session_id *session_id_remote)
{
    uint8_t count;
    ack->len = 0;

    if (!buf_read(buf, &count, sizeof(count)))
    {
        return false;
    }
    for (int i = 0; i < count; ++i)
    {
        packet_id_type net_pid;
        if (!buf_read(buf, &net_pid, sizeof(net_pid)))
        {
            return false;
        }
        if (ack->len >= RELIABLE_ACK_SIZE)
        {
            return false;
        }
        packet_id_type pid = ntohpid(net_pid);
        ack->packet_id[ack->len++] = pid;
    }
    if (count)
    {
        if (!session_id_read(session_id_remote, buf))
        {
            return false;
        }
    }
    return true;
}

/**
 * Copies the first n acks from \c ack to \c ack_mru
 */
void
copy_acks_to_mru(struct reliable_ack *ack, struct reliable_ack *ack_mru, int n)
{
    ASSERT(ack->len >= n);
    /* This loop is backward to ensure the same order as in ack */
    for (int i = n-1; i >= 0; i--)
    {
        packet_id_type id = ack->packet_id[i];

        /* Handle special case of ack_mru empty */
        if (ack_mru->len == 0)
        {
            ack_mru->len = 1;
            ack_mru->packet_id[0] = id;
        }

        bool idfound = false;

        /* Move all existing entries one to the right */
        packet_id_type move = id;

        for (int j = 0; j < ack_mru->len; j++)
        {
            packet_id_type tmp = ack_mru->packet_id[j];
            ack_mru->packet_id[j] = move;
            move = tmp;

            if (move == id)
            {
                idfound = true;
                break;
            }
        }

        if (!idfound && ack_mru->len < RELIABLE_ACK_SIZE)
        {
            ack_mru->packet_id[ack_mru->len] = move;
            ack_mru->len++;
        }
    }
}

/* write a packet ID acknowledgement record to buf, */
/* removing all acknowledged entries from ack */
bool
reliable_ack_write(struct reliable_ack *ack,
                   struct reliable_ack *ack_mru,
                   struct buffer *buf,
                   const struct session_id *sid, int max, bool prepend)
{
    int i, j;
    uint8_t n;
    struct buffer sub;

    n = ack->len;
    if (n > max)
    {
        n = max;
    }

    copy_acks_to_mru(ack, ack_mru, n);

    /* Number of acks we can resend that still fit into the packet */
    uint8_t total_acks = min_int(max, ack_mru->len);

    sub = buf_sub(buf, ACK_SIZE(total_acks), prepend);
    if (!BDEF(&sub))
    {
        goto error;
    }
    ASSERT(buf_write_u8(&sub, total_acks));

    /* Write the actual acks to the packets. Since we copied the acks that
     * are going out now already to the front of ack_mru we can fetch all
     * acks from ack_mru */
    for (i = 0; i < total_acks; ++i)
    {
        packet_id_type pid = ack_mru->packet_id[i];
        packet_id_type net_pid = htonpid(pid);
        ASSERT(buf_write(&sub, &net_pid, sizeof(net_pid)));
        dmsg(D_REL_DEBUG, "ACK write ID " packet_id_format " (ack->len=%d, n=%d)", (packet_id_print_type)pid, ack->len, n);
    }
    if (total_acks)
    {
        ASSERT(session_id_defined(sid));
        ASSERT(session_id_write(sid, &sub));
    }
    if (n)
    {
        for (i = 0, j = n; j < ack->len; )
        {
            ack->packet_id[i++] = ack->packet_id[j++];
        }
        ack->len = i;
    }

    return true;

error:
    return false;
}

/* print a reliable ACK record coming off the wire */
const char *
reliable_ack_print(struct buffer *buf, bool verbose, struct gc_arena *gc)
{
    int i;
    uint8_t n_ack;
    struct session_id sid_ack;
    packet_id_type pid;
    struct buffer out = alloc_buf_gc(256, gc);

    buf_printf(&out, "[");
    if (!buf_read(buf, &n_ack, sizeof(n_ack)))
    {
        goto done;
    }
    for (i = 0; i < n_ack; ++i)
    {
        if (!buf_read(buf, &pid, sizeof(pid)))
        {
            goto done;
        }
        pid = ntohpid(pid);
        buf_printf(&out, " " packet_id_format, (packet_id_print_type)pid);
    }
    if (n_ack)
    {
        if (!session_id_read(&sid_ack, buf))
        {
            goto done;
        }
        if (verbose)
        {
            buf_printf(&out, " sid=%s", session_id_print(&sid_ack, gc));
        }
    }

done:
    buf_printf(&out, " ]");
    return BSTR(&out);
}

/*
 * struct reliable member functions.
 */

void
reliable_init(struct reliable *rel, int buf_size, int offset, int array_size, bool hold)
{
    int i;

    CLEAR(*rel);
    ASSERT(array_size > 0 && array_size <= RELIABLE_CAPACITY);
    rel->hold = hold;
    rel->size = array_size;
    rel->offset = offset;
    for (i = 0; i < rel->size; ++i)
    {
        struct reliable_entry *e = &rel->array[i];
        e->buf = alloc_buf(buf_size);
        ASSERT(buf_init(&e->buf, offset));
    }
}

void
reliable_free(struct reliable *rel)
{
    if (!rel)
    {
        return;
    }
    int i;
    for (i = 0; i < rel->size; ++i)
    {
        struct reliable_entry *e = &rel->array[i];
        free_buf(&e->buf);
    }
    free(rel);
}

/* no active buffers? */
bool
reliable_empty(const struct reliable *rel)
{
    int i;
    for (i = 0; i < rel->size; ++i)
    {
        const struct reliable_entry *e = &rel->array[i];
        if (e->active)
        {
            return false;
        }
    }
    return true;
}

/* del acknowledged items from send buf */
void
reliable_send_purge(struct reliable *rel, const struct reliable_ack *ack)
{
    int i, j;
    for (i = 0; i < ack->len; ++i)
    {
        packet_id_type pid = ack->packet_id[i];
        for (j = 0; j < rel->size; ++j)
        {
            struct reliable_entry *e = &rel->array[j];
            if (e->active && e->packet_id == pid)
            {
                dmsg(D_REL_DEBUG,
                     "ACK received for pid " packet_id_format ", deleting from send buffer",
                     (packet_id_print_type)pid);
#if 0
                /* DEBUGGING -- how close were we timing out on ACK failure and resending? */
                {
                    if (e->next_try)
                    {
                        const interval_t wake = e->next_try - now;
                        msg(M_INFO, "ACK " packet_id_format ", wake=%d", pid, wake);
                    }
                }
#endif
                e->active = false;
            }
            else if (e->active && e->packet_id < pid)
            {
                /* We have received an ACK for a packet with a higher PID. Either
                 * we have received ACKs out of or order or the packet has been
                 * lost. We count the number of ACKs to determine if we should
                 * resend it early. */
                e->n_acks++;
            }
        }
    }
}

#ifdef ENABLE_DEBUG
/* print the current sequence of active packet IDs */
static const char *
reliable_print_ids(const struct reliable *rel, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(256, gc);
    int i;

    buf_printf(&out, "[" packet_id_format "]", (packet_id_print_type)rel->packet_id);
    for (i = 0; i < rel->size; ++i)
    {
        const struct reliable_entry *e = &rel->array[i];
        if (e->active)
        {
            buf_printf(&out, " " packet_id_format, (packet_id_print_type)e->packet_id);
        }
    }
    return BSTR(&out);
}
#endif /* ENABLE_DEBUG */

/* true if at least one free buffer available */
bool
reliable_can_get(const struct reliable *rel)
{
    struct gc_arena gc = gc_new();
    int i;
    for (i = 0; i < rel->size; ++i)
    {
        const struct reliable_entry *e = &rel->array[i];
        if (!e->active)
        {
            return true;
        }
    }
    dmsg(D_REL_LOW, "ACK no free receive buffer available: %s", reliable_print_ids(rel, &gc));
    gc_free(&gc);
    return false;
}

/* make sure that incoming packet ID isn't a replay */
bool
reliable_not_replay(const struct reliable *rel, packet_id_type id)
{
    struct gc_arena gc = gc_new();
    int i;
    if (reliable_pid_min(id, rel->packet_id))
    {
        goto bad;
    }
    for (i = 0; i < rel->size; ++i)
    {
        const struct reliable_entry *e = &rel->array[i];
        if (e->active && e->packet_id == id)
        {
            goto bad;
        }
    }
    gc_free(&gc);
    return true;

bad:
    dmsg(D_REL_DEBUG, "ACK " packet_id_format " is a replay: %s", (packet_id_print_type)id, reliable_print_ids(rel, &gc));
    gc_free(&gc);
    return false;
}

/* make sure that incoming packet ID won't deadlock the receive buffer */
bool
reliable_wont_break_sequentiality(const struct reliable *rel, packet_id_type id)
{
    struct gc_arena gc = gc_new();

    const int ret = reliable_pid_in_range2(id, rel->packet_id, rel->size);

    if (!ret)
    {
        dmsg(D_REL_LOW, "ACK " packet_id_format " breaks sequentiality: %s",
             (packet_id_print_type)id, reliable_print_ids(rel, &gc));
    }

    dmsg(D_REL_DEBUG, "ACK RWBS rel->size=%d rel->packet_id=%08x id=%08x ret=%d", rel->size, rel->packet_id, id, ret);

    gc_free(&gc);
    return ret;
}

/* grab a free buffer */
struct buffer *
reliable_get_buf(struct reliable *rel)
{
    int i;
    for (i = 0; i < rel->size; ++i)
    {
        struct reliable_entry *e = &rel->array[i];
        if (!e->active)
        {
            ASSERT(buf_init(&e->buf, rel->offset));
            return &e->buf;
        }
    }
    return NULL;
}

int
reliable_get_num_output_sequenced_available(struct reliable *rel)
{
    struct gc_arena gc = gc_new();
    packet_id_type min_id = 0;
    bool min_id_defined = false;

    /* find minimum active packet_id */
    for (int i = 0; i < rel->size; ++i)
    {
        const struct reliable_entry *e = &rel->array[i];
        if (e->active)
        {
            if (!min_id_defined || reliable_pid_min(e->packet_id, min_id))
            {
                min_id_defined = true;
                min_id = e->packet_id;
            }
        }
    }

    int ret = rel->size;
    if (min_id_defined)
    {
        ret -= subtract_pid(rel->packet_id, min_id);
    }
    gc_free(&gc);
    return ret;
}

/* grab a free buffer, fail if buffer clogged by unacknowledged low packet IDs */
struct buffer *
reliable_get_buf_output_sequenced(struct reliable *rel)
{
    struct gc_arena gc = gc_new();
    int i;
    packet_id_type min_id = 0;
    bool min_id_defined = false;
    struct buffer *ret = NULL;

    /* find minimum active packet_id */
    for (i = 0; i < rel->size; ++i)
    {
        const struct reliable_entry *e = &rel->array[i];
        if (e->active)
        {
            if (!min_id_defined || reliable_pid_min(e->packet_id, min_id))
            {
                min_id_defined = true;
                min_id = e->packet_id;
            }
        }
    }

    if (!min_id_defined || reliable_pid_in_range1(rel->packet_id, min_id, rel->size))
    {
        ret = reliable_get_buf(rel);
    }
    else
    {
        dmsg(D_REL_LOW, "ACK output sequence broken: %s", reliable_print_ids(rel, &gc));
    }
    gc_free(&gc);
    return ret;
}

/* get active buffer for next sequentially increasing key ID */
struct reliable_entry *
reliable_get_entry_sequenced(struct reliable *rel)
{
    int i;
    for (i = 0; i < rel->size; ++i)
    {
        struct reliable_entry *e = &rel->array[i];
        if (e->active && e->packet_id == rel->packet_id)
        {
            return e;
        }
    }
    return NULL;
}

/* return true if reliable_send would return a non-NULL result */
bool
reliable_can_send(const struct reliable *rel)
{
    struct gc_arena gc = gc_new();
    int i;
    int n_active = 0, n_current = 0;
    for (i = 0; i < rel->size; ++i)
    {
        const struct reliable_entry *e = &rel->array[i];
        if (e->active)
        {
            ++n_active;
            if (now >= e->next_try || e->n_acks >= N_ACK_RETRANSMIT)
            {
                ++n_current;
            }
        }
    }
    dmsg(D_REL_DEBUG, "ACK reliable_can_send active=%d current=%d : %s",
         n_active,
         n_current,
         reliable_print_ids(rel, &gc));

    gc_free(&gc);
    return n_current > 0 && !rel->hold;
}

/* return next buffer to send to remote */
struct buffer *
reliable_send(struct reliable *rel, int *opcode)
{
    int i;
    struct reliable_entry *best = NULL;
    const time_t local_now = now;

    for (i = 0; i < rel->size; ++i)
    {
        struct reliable_entry *e = &rel->array[i];

        /* If N_ACK_RETRANSMIT later packets have received ACKs, we assume
         * that the packet was lost and resend it even if the timeout has
         * not expired yet. */
        if (e->active
            && (e->n_acks >= N_ACK_RETRANSMIT || local_now >= e->next_try))
        {
            if (!best || reliable_pid_min(e->packet_id, best->packet_id))
            {
                best = e;
            }
        }
    }
    if (best)
    {
        /* exponential backoff */
        best->next_try = local_now + best->timeout;
        best->timeout *= 2;
        best->n_acks = 0;
        *opcode = best->opcode;
        dmsg(D_REL_DEBUG, "ACK reliable_send ID " packet_id_format " (size=%d to=%d)",
             (packet_id_print_type)best->packet_id, best->buf.len,
             (int)(best->next_try - local_now));
        return &best->buf;
    }
    return NULL;
}

/* schedule all pending packets for immediate retransmit */
void
reliable_schedule_now(struct reliable *rel)
{
    int i;
    dmsg(D_REL_DEBUG, "ACK reliable_schedule_now");
    rel->hold = false;
    for (i = 0; i < rel->size; ++i)
    {
        struct reliable_entry *e = &rel->array[i];
        if (e->active)
        {
            e->next_try = now;
            e->timeout = rel->initial_timeout;
        }
    }
}

/* in how many seconds should we wake up to check for timeout */
/* if we return BIG_TIMEOUT, nothing to wait for */
interval_t
reliable_send_timeout(const struct reliable *rel)
{
    struct gc_arena gc = gc_new();
    interval_t ret = BIG_TIMEOUT;
    int i;
    const time_t local_now = now;

    for (i = 0; i < rel->size; ++i)
    {
        const struct reliable_entry *e = &rel->array[i];
        if (e->active)
        {
            if (e->next_try <= local_now)
            {
                ret = 0;
                break;
            }
            else
            {
                ret = min_int(ret, e->next_try - local_now);
            }
        }
    }

    dmsg(D_REL_DEBUG, "ACK reliable_send_timeout %d %s",
         (int) ret,
         reliable_print_ids(rel, &gc));

    gc_free(&gc);
    return ret;
}

/*
 * Enable an incoming buffer previously returned by a get function as active.
 */

void
reliable_mark_active_incoming(struct reliable *rel, struct buffer *buf,
                              packet_id_type pid, int opcode)
{
    int i;
    for (i = 0; i < rel->size; ++i)
    {
        struct reliable_entry *e = &rel->array[i];
        if (buf == &e->buf)
        {
            e->active = true;

            /* packets may not arrive in sequential order */
            e->packet_id = pid;

            /* check for replay */
            ASSERT(!reliable_pid_min(pid, rel->packet_id));

            e->opcode = opcode;
            e->next_try = 0;
            e->timeout = 0;
            e->n_acks = 0;
            dmsg(D_REL_DEBUG, "ACK mark active incoming ID " packet_id_format, (packet_id_print_type)e->packet_id);
            return;
        }
    }
    ASSERT(0);                  /* buf not found in rel */
}

/*
 * Enable an outgoing buffer previously returned by a get function as active.
 */

void
reliable_mark_active_outgoing(struct reliable *rel, struct buffer *buf, int opcode)
{
    int i;
    for (i = 0; i < rel->size; ++i)
    {
        struct reliable_entry *e = &rel->array[i];
        if (buf == &e->buf)
        {
            /* Write mode, increment packet_id (i.e. sequence number)
             * linearly and prepend id to packet */
            packet_id_type net_pid;
            e->packet_id = rel->packet_id++;
            net_pid = htonpid(e->packet_id);
            ASSERT(buf_write_prepend(buf, &net_pid, sizeof(net_pid)));
            e->active = true;
            e->opcode = opcode;
            e->next_try = 0;
            e->timeout = rel->initial_timeout;
            dmsg(D_REL_DEBUG, "ACK mark active outgoing ID " packet_id_format, (packet_id_print_type)e->packet_id);
            return;
        }
    }
    ASSERT(0);                  /* buf not found in rel */
}

/* delete a buffer previously activated by reliable_mark_active() */
void
reliable_mark_deleted(struct reliable *rel, struct buffer *buf)
{
    int i;
    for (i = 0; i < rel->size; ++i)
    {
        struct reliable_entry *e = &rel->array[i];
        if (buf == &e->buf)
        {
            e->active = false;
            rel->packet_id = e->packet_id + 1;
            return;
        }
    }
    ASSERT(0);
}

#if 0

void
reliable_ack_debug_print(const struct reliable_ack *ack, char *desc)
{
    int i;

    printf("********* struct reliable_ack %s\n", desc);
    for (i = 0; i < ack->len; ++i)
    {
        printf("  %d: " packet_id_format "\n", i, (packet_id_print_type) ack->packet_id[i]);
    }
}

void
reliable_debug_print(const struct reliable *rel, char *desc)
{
    int i;
    update_time();

    printf("********* struct reliable %s\n", desc);
    printf("  initial_timeout=%d\n", (int)rel->initial_timeout);
    printf("  packet_id=" packet_id_format "\n", rel->packet_id);
    printf("  now=%" PRIi64 "\n", (int64_t)now);
    for (i = 0; i < rel->size; ++i)
    {
        const struct reliable_entry *e = &rel->array[i];
        if (e->active)
        {
            printf("  %d: packet_id=" packet_id_format " len=%d", i, e->packet_id, e->buf.len);
            printf(" next_try=%" PRIi64, (int64_t)e->next_try);
            printf("\n");
        }
    }
}

#endif /* if 0 */
