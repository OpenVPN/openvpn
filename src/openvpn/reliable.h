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


/**
 * @file
 * Reliability Layer module header file.
 */


#if defined(ENABLE_CRYPTO) && defined(ENABLE_SSL)

#ifndef RELIABLE_H
#define RELIABLE_H

#include "basic.h"
#include "buffer.h"
#include "packet_id.h"
#include "session_id.h"
#include "mtu.h"

/** @addtogroup reliable
 *  @{ */


#define EXPONENTIAL_BACKOFF

#define RELIABLE_ACK_SIZE 8     /**< The maximum number of packet IDs
                                 *   waiting to be acknowledged which can
                                 *   be stored in one \c reliable_ack
                                 *   structure. */

#define RELIABLE_CAPACITY 8	/**< The maximum number of packets that
                                 *   the reliability layer for one VPN
                                 *   tunnel in one direction can store. */

/**
 * The acknowledgment structure in which packet IDs are stored for later
 * acknowledgment.
 */
struct reliable_ack
{
  int len;
  packet_id_type packet_id[RELIABLE_ACK_SIZE];
};

/**
 * The structure in which the reliability layer stores a single incoming
 * or outgoing packet.
 */
struct reliable_entry
{
  bool active;
  interval_t timeout;
  time_t next_try;
  packet_id_type packet_id;
  int opcode;
  struct buffer buf;
};

/**
 * The reliability layer storage structure for one VPN tunnel's control
 * channel in one direction.
 */
struct reliable
{
  int size;
  interval_t initial_timeout;
  packet_id_type packet_id;
  int offset;
  bool hold; /* don't xmit until reliable_schedule_now is called */
  struct reliable_entry array[RELIABLE_CAPACITY];
};


/**************************************************************************/
/** @name Functions for processing incoming acknowledgments
 *  @{ */

/**
 * Read an acknowledgment record from a received packet.
 *
 * This function reads the packet ID acknowledgment record from the packet
 * contained in \a buf.  If the record contains acknowledgments, these are
 * stored in \a ack.  This function also compares the packet's session ID
 * with the expected session ID \a sid, which should be equal.
 *
 * @param ack The acknowledgment structure in which received
 *     acknowledgments are to be stored.
 * @param buf The buffer containing the packet.
 * @param sid The expected session ID to compare to the session ID in
 *     the packet.
 *
 * @return
 * @li True, if processing was successful.
 * @li False, if an error occurs during processing.
 */
bool reliable_ack_read (struct reliable_ack *ack,
			struct buffer *buf, const struct session_id *sid);

/**
 * Remove acknowledged packets from a reliable structure.
 *
 * @param rel The reliable structure storing sent packets.
 * @param ack The acknowledgment structure containing received
 *     acknowledgments.
 */
void reliable_send_purge (struct reliable *rel, struct reliable_ack *ack);

/** @} name Functions for processing incoming acknowledgments */


/**************************************************************************/
/** @name Functions for processing outgoing acknowledgments
 *  @{ */

/**
 * Check whether an acknowledgment structure contains any
 *     packet IDs to be acknowledged.
 *
 * @param ack The acknowledgment structure to check.
 *
 * @return
 * @li True, if the acknowledgment structure is empty.
 * @li False, if there are packet IDs to be acknowledged.
 */
static inline bool
reliable_ack_empty (struct reliable_ack *ack)
{
  return !ack->len;
}

/**
 * Write a packet ID acknowledgment record to a buffer.
 *
 * @param ack The acknowledgment structure containing packet IDs to be
 *     acknowledged.
 * @param buf The buffer into which the acknowledgment record will be
 *     written.
 * @param sid The session ID of the VPN tunnel associated with the
 *     packet IDs to be acknowledged.
 * @param max The maximum number of acknowledgments to be written in
 *     the record.
 * @param prepend If true, prepend the acknowledgment record in the
 *     buffer; if false, write into the buffer's current position.
 *
 * @return
 * @li True, if processing was successful.
 * @li False, if an error occurs during processing.
 */
bool reliable_ack_write (struct reliable_ack *ack,
			 struct buffer *buf,
			 const struct session_id *sid, int max, bool prepend);

/** @} name Functions for processing outgoing acknowledgments */


/**************************************************************************/
/** @name Functions for initialization and cleanup
 *  @{ */

/**
 * Initialize a reliable structure.
 *
 * @param rel The reliable structure to initialize.
 * @param buf_size The size of the buffers in which packets will be
 *     stored.
 * @param offset The size of reserved space at the beginning of the
 *     buffers to allow efficient header prepending.
 * @param array_size The number of packets that this reliable
 *     structure can store simultaneously.
 * @param hold description
 */
void reliable_init (struct reliable *rel, int buf_size, int offset, int array_size, bool hold);

/**
 * Free allocated memory associated with a reliable structure.
 *
 * @param rel The reliable structured to clean up.
 */
void reliable_free (struct reliable *rel);

/* add to extra_frame the maximum number of bytes we will need for reliable_ack_write */
void reliable_ack_adjust_frame_parameters (struct frame* frame, int max);

/** @} name Functions for initialization and cleanup */


/**************************************************************************/
/** @name Functions for inserting incoming packets
 *  @{ */

/**
 * Check whether a reliable structure has any free buffers
 *     available for use.
 *
 * @param rel The reliable structure to check.
 *
 * @return
 * @li True, if at least one buffer is available for use.
 * @li False, if all the buffers are active.
 */
bool reliable_can_get (const struct reliable *rel);

/**
 * Check that a received packet's ID is not a replay.
 *
 * @param rel The reliable structure for handling this VPN tunnel's
 *     received packets.
 * @param id The packet ID of the received packet.
 *
 * @return
 * @li True, if the packet ID is not a replay.
 * @li False, if the packet ID is a replay.
 */
bool reliable_not_replay (const struct reliable *rel, packet_id_type id);

/**
 * Check that a received packet's ID can safely be stored in
 *     the reliable structure's processing window.
 *
 * This function checks the difference between the received packet's ID
 * and the lowest non-acknowledged packet ID in the given reliable
 * structure.  If that difference is larger than the total number of
 * packets which can be stored, then this packet cannot be stored safely,
 * because the reliable structure could possibly fill up without leaving
 * room for all intervening packets.  In that case, this received packet
 * could break the reliable structure's sequentiality, and must therefore
 * be discarded.
 *
 * @param rel The reliable structure for handling this VPN tunnel's
 *     received packets.
 * @param id The packet ID of the received packet.
 *
 * @return
 * @li True, if the packet can safely be stored.
 * @li False, if the packet does not fit safely in the reliable
 *     structure's processing window.
 */
bool reliable_wont_break_sequentiality (const struct reliable *rel, packet_id_type id);

/**
 * Read the packet ID of a received packet.
 *
 * @param buf The buffer containing the received packet.
 * @param pid A pointer where the packet's packet ID will be written.
 *
 * @return
 * @li True, if processing was successful.
 * @li False, if an error occurs during processing.
 */
bool reliable_ack_read_packet_id (struct buffer *buf, packet_id_type *pid);

/**
 * Get the buffer of a free %reliable entry in which to store a
 *     packet.
 *
 * @param rel The reliable structure in which to search for a free
 *     entry.
 *
 * @return A pointer to a buffer of a free entry in the \a rel
 *     reliable structure.  If there are no free entries available, this
 *     function returns NULL.
 */
struct buffer *reliable_get_buf (struct reliable *rel);

/**
 * Mark the %reliable entry associated with the given buffer as active
 * incoming.
 *
 * @param rel The reliable structure associated with this packet.
 * @param buf The buffer into which the packet has been copied.
 * @param pid The packet's packet ID.
 * @param opcode The packet's opcode.
 */
void reliable_mark_active_incoming (struct reliable *rel, struct buffer *buf,
				    packet_id_type pid, int opcode);

/**
 * Record a packet ID for later acknowledgment.
 *
 * @param ack The acknowledgment structure which stores this VPN
 *     tunnel's packet IDs for later acknowledgment.
 * @param pid The packet ID of the received packet which should be
 *     acknowledged.
 *
 * @return
 * @li True, if the packet ID was added to \a ack.
 * @li False, if the packet ID was already present in \a ack or \a ack
 *     has no free space to store any more packet IDs.
 */
bool reliable_ack_acknowledge_packet_id (struct reliable_ack *ack, packet_id_type pid);

/** @} name Functions for inserting incoming packets */


/**************************************************************************/
/** @name Functions for extracting incoming packets
 *  @{ */

/**
 * Get the buffer of the next sequential and active entry.
 *
 * @param rel The reliable structure from which to retrieve the
 *     buffer.
 *
 * @return A pointer to the buffer of the entry with the next
 *     sequential key ID.  If no such entry is present, this function
 *     returns NULL.
 */
struct buffer *reliable_get_buf_sequenced (struct reliable *rel);

/**
 * Remove an entry from a reliable structure.
 *
 * @param rel The reliable structure associated with the given buffer.
 * @param buf The buffer of the reliable entry which is to be removed.
 * @param inc_pid If true, the reliable structure's packet ID counter
 *     will be incremented.
 */
void reliable_mark_deleted (struct reliable *rel, struct buffer *buf, bool inc_pid);

/** @} name Functions for extracting incoming packets */


/**************************************************************************/
/** @name Functions for inserting outgoing packets
 *  @{ */

/**
 * Get the buffer of free reliable entry and check whether the
 *     outgoing acknowledgment sequence is still okay.
 *
 * @param rel The reliable structure in which to search for a free
 *     entry.
 *
 * @return A pointer to a buffer of a free entry in the \a rel
 *     reliable structure.  If there are no free entries available, this
 *     function returns NULL.  If the outgoing acknowledgment sequence is
 *     broken, this function also returns NULL.
 */
struct buffer *reliable_get_buf_output_sequenced (struct reliable *rel);

/**
 * Mark the reliable entry associated with the given buffer as
 *     active outgoing.
 *
 * @param rel The reliable structure for handling this VPN tunnel's
 *     outgoing packets.
 * @param buf The buffer previously returned by \c
 *     reliable_get_buf_output_sequenced() into which the packet has been
 *     copied.
 * @param opcode The packet's opcode.
 */
void reliable_mark_active_outgoing (struct reliable *rel, struct buffer *buf, int opcode);

/** @} name Functions for inserting outgoing packets */


/**************************************************************************/
/** @name Functions for extracting outgoing packets
 *  @{ */

/**
 * Check whether a reliable structure has any active entries
 *     ready to be (re)sent.
 *
 * @param rel The reliable structure to check.
 *
 * @return
 * @li True, if there are active entries ready to be (re)sent
 *     president.
 * @li False, if there are no active entries, or the active entries
 *     are not yet ready for resending.
 */
bool reliable_can_send (const struct reliable *rel);

/**
 * Get the next packet to send to the remote peer.
 *
 * This function looks for the active entry ready for (re)sending with the
 * lowest packet ID, and returns the buffer associated with it.  This
 * function also resets the timeout after which that entry will become
 * ready for resending again.
 *
 * @param rel The reliable structure to check.
 * @param opcode A pointer to an integer in which this function will
 *     store the opcode of the next packet to be sent.
 *
 * @return A pointer to the buffer of the next entry to be sent, or
 *     NULL if there are no entries ready for (re)sending present in the
 *     reliable structure.  If a valid pointer is returned, then \a opcode
 *     will point to the opcode of that packet.
 */
struct buffer *reliable_send (struct reliable *rel, int *opcode);

/** @} name Functions for extracting outgoing packets */


/**************************************************************************/
/** @name Miscellaneous functions
 *  @{ */

/**
 * Check whether a reliable structure is empty.
 *
 * @param rel The reliable structure to check.
 *
 * @return
 * @li True, if there are no active entries in the given reliable
 *     structure.
 * @li False, if there is at least one active entry present.
 */
bool reliable_empty (const struct reliable *rel);

/**
 * Determined how many seconds until the earliest resend should
 *     be attempted.
 *
 * @param rel The reliable structured to check.
 *
 * @return The interval in seconds until the earliest resend attempt
 *     of the outgoing packets stored in the \a rel reliable structure. If
 *     the next time for attempting resending of one or more packets has
 *     already passed, this function will return 0.
 */
interval_t reliable_send_timeout (const struct reliable *rel);

/**
 * Reschedule all entries of a reliable structure to be ready
 *     for (re)sending immediately.
 *
 * @param rel The reliable structure of which the entries should be
 *     modified.
 */
void reliable_schedule_now (struct reliable *rel);

void reliable_debug_print (const struct reliable *rel, char *desc);

/* set sending timeout (after this time we send again until ACK) */
static inline void
reliable_set_timeout (struct reliable *rel, interval_t timeout)
{
  rel->initial_timeout = timeout;
}

/* print a reliable ACK record coming off the wire */
const char *reliable_ack_print (struct buffer *buf, bool verbose, struct gc_arena *gc);

void reliable_ack_debug_print (const struct reliable_ack *ack, char *desc);

/** @} name Miscellaneous functions */


/** @} addtogroup reliable */


#endif /* RELIABLE_H */
#endif /* ENABLE_CRYPTO && ENABLE_SSL */
