/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * This routines implement a reliability layer on top of UDP,
 * so that TLS can be run over UDP.
 */

#if defined(USE_CRYPTO) && defined(USE_SSL)

#ifndef RELIABLE_H
#define RELIABLE_H

#include "basic.h"
#include "buffer.h"
#include "packet_id.h"
#include "session_id.h"
#include "mtu.h"

#define EXPONENTIAL_BACKOFF

#define RELIABLE_ACK_SIZE 8

struct reliable_ack
{
  int len;
  packet_id_type packet_id[RELIABLE_ACK_SIZE];
};

/* no active buffers? */
static inline bool
reliable_ack_empty (struct reliable_ack *ack)
{
  return !ack->len;
}

/* get a packet_id from buf */
bool reliable_ack_read_packet_id (struct buffer *buf, packet_id_type *pid);

/* acknowledge a packet_id by adding it to a struct reliable_ack */
bool reliable_ack_acknowledge_packet_id (struct reliable_ack *ack, packet_id_type pid);

/* read a packet ID acknowledgement record from buf */
bool reliable_ack_read (struct reliable_ack *ack,
			struct buffer *buf, const struct session_id *sid);

/* write a packet ID acknowledgement record to buf */
bool reliable_ack_write (struct reliable_ack *ack,
			 struct buffer *buf,
			 const struct session_id *sid, int max, bool prepend);

/* print a reliable ACK record coming off the wire */
const char *reliable_ack_print (struct buffer *buf, bool verbose, struct gc_arena *gc);

/* add to extra_frame the maximum number of bytes we will need for reliable_ack_write */
void reliable_ack_adjust_frame_parameters (struct frame* frame, int max);

void reliable_ack_debug_print (const struct reliable_ack *ack, char *desc);

#define RELIABLE_CAPACITY 8

struct reliable_entry
{
  bool active;
  interval_t timeout;
  time_t next_try;
  packet_id_type packet_id;
  int opcode;
  struct buffer buf;
};

struct reliable
{
  int size;
  interval_t initial_timeout;
  packet_id_type packet_id;
  int offset;
  bool hold; /* don't xmit until reliable_schedule_now is called */
  struct reliable_entry array[RELIABLE_CAPACITY];
};

void reliable_debug_print (const struct reliable *rel, char *desc);

/* set sending timeout (after this time we send again until ACK) */
static inline void
reliable_set_timeout (struct reliable *rel, interval_t timeout)
{
  rel->initial_timeout = timeout;
}

void reliable_init (struct reliable *rel, int buf_size, int offset, int array_size, bool hold);

void reliable_free (struct reliable *rel);

/* no active buffers? */
bool reliable_empty (const struct reliable *rel);

/* in how many seconds should we wake up to check for timeout */
interval_t reliable_send_timeout (const struct reliable *rel);

/* del acknowledged items from send buf */
void reliable_send_purge (struct reliable *rel, struct reliable_ack *ack);

/* true if at least one free buffer available */
bool reliable_can_get (const struct reliable *rel);

/* make sure that incoming packet ID isn't a replay */
bool reliable_not_replay (const struct reliable *rel, packet_id_type id);

/* make sure that incoming packet ID won't deadlock the receive buffer */
bool reliable_wont_break_sequentiality (const struct reliable *rel, packet_id_type id);

/* grab a free buffer */
struct buffer *reliable_get_buf (struct reliable *rel);

/* grab a free buffer, fail if buffer clogged by unacknowledged low packet IDs */
struct buffer *reliable_get_buf_output_sequenced (struct reliable *rel);

/* get active buffer for next sequentially increasing key ID */
struct buffer *reliable_get_buf_sequenced (struct reliable *rel);

/* return true if reliable_send would return a non-NULL result */
bool reliable_can_send (const struct reliable *rel);

/* return next buffer to send to remote */
struct buffer *reliable_send (struct reliable *rel, int *opcode);

/* schedule all pending packets for immediate retransmit */
void reliable_schedule_now (struct reliable *rel);

/* enable an incoming buffer previously returned by a get function as active */
void reliable_mark_active_incoming (struct reliable *rel, struct buffer *buf,
				    packet_id_type pid, int opcode);

/* enable an outgoing buffer previously returned by a get function as active. */
void reliable_mark_active_outgoing (struct reliable *rel, struct buffer *buf, int opcode);

/* delete a buffer previously activated by reliable_mark_active() */
void reliable_mark_deleted (struct reliable *rel, struct buffer *buf, bool inc_pid);

#endif /* RELIABLE_H */
#endif /* USE_CRYPTO && USE_SSL */
