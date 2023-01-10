/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
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
 * These routines are designed to catch replay attacks,
 * where a man-in-the-middle captures packets and then
 * attempts to replay them back later.
 */

#ifndef PACKET_ID_H
#define PACKET_ID_H

#include "circ_list.h"
#include "buffer.h"
#include "error.h"
#include "otime.h"

#if 1
/*
 * These are the types that members of
 * a struct packet_id_net are converted
 * to for network transmission.
 */
typedef uint32_t packet_id_type;
#define PACKET_ID_MAX UINT32_MAX
typedef uint32_t net_time_t;

/*
 * In TLS mode, when a packet ID gets to this level,
 * start thinking about triggering a new
 * SSL/TLS handshake.
 */
#define PACKET_ID_WRAP_TRIGGER 0xFF000000

/* convert a packet_id_type from host to network order */
#define htonpid(x) htonl(x)

/* convert a packet_id_type from network to host order */
#define ntohpid(x) ntohl(x)

/* convert a time_t in host order to a net_time_t in network order */
#define htontime(x) htonl((net_time_t)x)

/* convert a net_time_t in network order to a time_t in host order */
#define ntohtime(x) ((time_t)ntohl(x))

#else  /* if 1 */

/*
 * DEBUGGING ONLY.
 * Make packet_id_type and net_time_t small
 * to test wraparound logic and corner cases.
 */

typedef uint8_t packet_id_type;
typedef uint16_t net_time_t;

#define PACKET_ID_WRAP_TRIGGER 0x80

#define htonpid(x) (x)
#define ntohpid(x) (x)
#define htontime(x) htons((net_time_t)x)
#define ntohtime(x) ((time_t)ntohs(x))

#endif /* if 1 */

/*
 * Printf formats for special types
 */
#define packet_id_format "%u"
typedef unsigned int packet_id_print_type;

/*
 * Maximum allowed backtrack in
 * sequence number due to packets arriving
 * out of order.
 */
#define MIN_SEQ_BACKTRACK 0
#define MAX_SEQ_BACKTRACK 65536
#define DEFAULT_SEQ_BACKTRACK 64

/*
 * Maximum allowed backtrack in
 * seconds due to packets arriving
 * out of order.
 */
#define MIN_TIME_BACKTRACK 0
#define MAX_TIME_BACKTRACK 600
#define DEFAULT_TIME_BACKTRACK 15

/*
 * Do a reap pass through the sequence number
 * array once every n seconds in order to
 * expire sequence numbers which can no longer
 * be accepted because they would violate
 * TIME_BACKTRACK.
 */
#define SEQ_REAP_INTERVAL 5

CIRC_LIST(seq_list, time_t);

/*
 * This is the data structure we keep on the receiving side,
 * to check that no packet-id (i.e. sequence number + optional timestamp)
 * is accepted more than once.
 */
struct packet_id_rec
{
    time_t last_reap;         /* last call of packet_id_reap */
    time_t time;              /* highest time stamp received */
    packet_id_type id;        /* highest sequence number received */
    int seq_backtrack;        /* set from --replay-window */
    int time_backtrack;       /* set from --replay-window */
    int max_backtrack_stat;   /* maximum backtrack seen so far */
    bool initialized;         /* true if packet_id_init was called */
    struct seq_list *seq_list; /* packet-id "memory" */
    const char *name;
    int unit;
};

/*
 * file to facilitate cross-session persistence
 * of time/id
 */
struct packet_id_persist
{
    const char *filename;
    int fd;
    time_t time;           /* time stamp */
    packet_id_type id;     /* sequence number */
    time_t time_last_written;
    packet_id_type id_last_written;
};

struct packet_id_persist_file_image
{
    time_t time;           /* time stamp */
    packet_id_type id;     /* sequence number */
};

/*
 * Keep a record of our current packet-id state
 * on the sending side.
 */
struct packet_id_send
{
    packet_id_type id;
    time_t time;
};

/*
 * Communicate packet-id over the wire.
 * A short packet-id is just a 32 bit
 * sequence number.  A long packet-id
 * includes a timestamp as well.
 *
 * Long packet-ids are used as IVs for
 * CFB/OFB ciphers.
 *
 * This data structure is always sent
 * over the net in network byte order,
 * by calling htonpid, ntohpid,
 * htontime, and ntohtime on the
 * data elements to change them
 * to and from standard sizes.
 *
 * In addition, time is converted to
 * a net_time_t before sending,
 * since openvpn always
 * uses a 32-bit time_t but some
 * 64 bit platforms use a
 * 64 bit time_t.
 */
struct packet_id_net
{
    packet_id_type id;
    time_t time; /* converted to net_time_t before transmission */
};

struct packet_id
{
    struct packet_id_send send;
    struct packet_id_rec rec;
};

void packet_id_init(struct packet_id *p, int seq_backtrack, int time_backtrack, const char *name, int unit);

void packet_id_free(struct packet_id *p);

/* should we accept an incoming packet id ? */
bool packet_id_test(struct packet_id_rec *p,
                    const struct packet_id_net *pin);

/* change our current state to reflect an accepted packet id */
void packet_id_add(struct packet_id_rec *p,
                   const struct packet_id_net *pin);

/* expire TIME_BACKTRACK sequence numbers */
void packet_id_reap(struct packet_id_rec *p);

/*
 * packet ID persistence
 */

/* initialize the packet_id_persist structure in a disabled state */
void packet_id_persist_init(struct packet_id_persist *p);

/* close the file descriptor if it is open, and switch to disabled state */
void packet_id_persist_close(struct packet_id_persist *p);

/* load persisted rec packet_id (time and id) only once from file, and set state to enabled */
void packet_id_persist_load(struct packet_id_persist *p, const char *filename);

/* save persisted rec packet_id (time and id) to file (only if enabled state) */
void packet_id_persist_save(struct packet_id_persist *p);

/* transfer packet_id_persist -> packet_id */
void packet_id_persist_load_obj(const struct packet_id_persist *p, struct packet_id *pid);

/* return an ascii string representing a packet_id_persist object */
const char *packet_id_persist_print(const struct packet_id_persist *p, struct gc_arena *gc);

/*
 * Read/write a packet ID to/from the buffer.  Short form is sequence number
 * only.  Long form is sequence number and timestamp.
 */

bool packet_id_read(struct packet_id_net *pin, struct buffer *buf, bool long_form);

/**
 * Write a packet ID to buf, and update the packet ID state.
 *
 * @param p             Packet ID state.
 * @param buf           Buffer to write the packet ID too
 * @param long_form     If true, also update and write time_t to buf
 * @param prepend       If true, prepend to buffer, otherwise append.
 *
 * @return true if successful, false otherwise.
 */
bool packet_id_write(struct packet_id_send *p, struct buffer *buf,
                     bool long_form, bool prepend);

/*
 * Inline functions.
 */

/** Is this struct packet_id initialized? */
static inline bool
packet_id_initialized(const struct packet_id *pid)
{
    return pid->rec.initialized;
}

/* are we in enabled state? */
static inline bool
packet_id_persist_enabled(const struct packet_id_persist *p)
{
    return p->fd >= 0;
}

/* transfer packet_id -> packet_id_persist */
static inline void
packet_id_persist_save_obj(struct packet_id_persist *p, const struct packet_id *pid)
{
    if (packet_id_persist_enabled(p) && pid->rec.time)
    {
        p->time = pid->rec.time;
        p->id = pid->rec.id;
    }
}

/**
 * Reset the current send packet id to its initial state.
 * Use very carefully (e.g. in the standalone reset packet context) to
 * avoid sending more than one packet with the same packet id (that is not
 * also a resend like the reset packet)
 *
 * @param p the packet structure to modify
 */
static inline void
reset_packet_id_send(struct packet_id_send *p)
{
    p->time = 0;
    p->id = 0;
}

const char *packet_id_net_print(const struct packet_id_net *pin, bool print_timestamp, struct gc_arena *gc);

static inline int
packet_id_size(bool long_form)
{
    return sizeof(packet_id_type) + (long_form ? sizeof(net_time_t) : 0);
}

static inline bool
packet_id_close_to_wrapping(const struct packet_id_send *p)
{
    return p->id >= PACKET_ID_WRAP_TRIGGER;
}

static inline bool
check_timestamp_delta(time_t remote, unsigned int max_delta)
{
    unsigned int abs;
    const time_t local_now = now;

    if (local_now >= remote)
    {
        abs = local_now - remote;
    }
    else
    {
        abs = remote - local_now;
    }
    return abs <= max_delta;
}

static inline void
packet_id_reap_test(struct packet_id_rec *p)
{
    if (p->last_reap + SEQ_REAP_INTERVAL <= now)
    {
        packet_id_reap(p);
    }
}

#endif /* PACKET_ID_H */
