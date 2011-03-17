/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
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

#ifndef OCC_H
#define OCC_H

#ifdef ENABLE_OCC

#include "forward.h"

/* OCC_STRING_SIZE must be set to sizeof (occ_magic) */
#define OCC_STRING_SIZE 16

/*
 * OCC (OpenVPN Configuration Control) protocol opcodes.
 */

#define OCC_REQUEST   0		/* request options string from peer */
#define OCC_REPLY     1		/* deliver options string to peer */

/*
 * Send an OCC_REQUEST once every OCC_INTERVAL
 * seconds until a reply is received.
 *
 * If we haven't received a reply after
 * OCC_N_TRIES, give up.
 */
#define OCC_INTERVAL_SECONDS 10
#define OCC_N_TRIES          12

/*
 * Other OCC protocol opcodes used to estimate the MTU empirically.
 */
#define OCC_MTU_LOAD_REQUEST   2	/* Ask peer to send a big packet to us */
#define OCC_MTU_LOAD           3	/* Send a big packet to peer */
#define OCC_MTU_REQUEST        4	/* Ask peer to tell us the largest
					   packet it has received from us so far */
#define OCC_MTU_REPLY          5	/* Send largest packet size to peer */

/*
 * Process one command from mtu_load_test_sequence
 * once every n seconds, if --mtu-test is specified.
 */
#define OCC_MTU_LOAD_INTERVAL_SECONDS 3

/*
 * Send an exit message to remote.
 */
#define OCC_EXIT               6

/*
 * Used to conduct a load test command sequence
 * of UDP connection for empirical MTU measurement.
 */
struct mtu_load_test
{
  int op;			/* OCC opcode to send to peer */
  int delta;			/* determine packet size to send by using
				   this delta against currently
				   configured MTU */
};

extern const uint8_t occ_magic[];

static inline bool
is_occ_msg (const struct buffer* buf)
{
  return buf_string_match_head (buf, occ_magic, OCC_STRING_SIZE);
}

void process_received_occ_msg (struct context *c);

#endif
#endif
