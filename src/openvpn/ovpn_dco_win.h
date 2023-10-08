/*
 *  ovpn-dco-win OpenVPN protocol accelerator for Windows
 *
 *  Copyright (C) 2020-2021 OpenVPN Inc <sales@openvpn.net>
 *
 *  Author:	Lev Stipakov <lev@openvpn.net>
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
 *
 *  This particular file (uapi.h) is also licensed using the MIT license (see COPYRIGHT.MIT).
 */

#pragma once
#ifndef _KERNEL_MODE
#include <winsock2.h>
#endif
#include <ws2def.h>
#include <ws2ipdef.h>

typedef enum {
	OVPN_PROTO_UDP,
	OVPN_PROTO_TCP
} OVPN_PROTO;

typedef struct _OVPN_NEW_PEER {
	union {
		SOCKADDR_IN Addr4;
		SOCKADDR_IN6 Addr6;
	} Local;

	union {
		SOCKADDR_IN Addr4;
		SOCKADDR_IN6 Addr6;
	} Remote;

	OVPN_PROTO Proto;
} OVPN_NEW_PEER, * POVPN_NEW_PEER;

typedef struct _OVPN_STATS {
	LONG LostInControlPackets;
	LONG LostOutControlPackets;

	LONG LostInDataPackets;
	LONG LostOutDataPackets;

	LONG ReceivedDataPackets;
	LONG ReceivedControlPackets;

	LONG SentControlPackets;
	LONG SentDataPackets;

	LONG64 TransportBytesSent;
	LONG64 TransportBytesReceived;

	LONG64 TunBytesSent;
	LONG64 TunBytesReceived;
} OVPN_STATS, * POVPN_STATS;

typedef enum _OVPN_KEY_SLOT {
	OVPN_KEY_SLOT_PRIMARY,
	OVPN_KEY_SLOT_SECONDARY
} OVPN_KEY_SLOT;

typedef enum _OVPN_CIPHER_ALG {
	OVPN_CIPHER_ALG_NONE,
	OVPN_CIPHER_ALG_AES_GCM,
	OVPN_CIPHER_ALG_CHACHA20_POLY1305
} OVPN_CIPHER_ALG;

typedef struct _OVPN_KEY_DIRECTION
{
	unsigned char Key[32];
	unsigned char KeyLen; // 16/24/32 -> AES-128-GCM/AES-192-GCM/AES-256-GCM
	unsigned char NonceTail[8];
} OVPN_KEY_DIRECTION;

typedef struct _OVPN_CRYPTO_DATA {
	OVPN_KEY_DIRECTION Encrypt;
	OVPN_KEY_DIRECTION Decrypt;
	OVPN_KEY_SLOT KeySlot;
	OVPN_CIPHER_ALG CipherAlg;
	unsigned char KeyId;
	int PeerId;
} OVPN_CRYPTO_DATA, * POVPN_CRYPTO_DATA;

typedef struct _OVPN_SET_PEER {
	LONG KeepaliveInterval;
	LONG KeepaliveTimeout;
	LONG MSS;
} OVPN_SET_PEER, * POVPN_SET_PEER;

typedef struct _OVPN_VERSION {
    LONG Major;
    LONG Minor;
    LONG Patch;
} OVPN_VERSION, * POVPN_VERSION;

#define OVPN_IOCTL_NEW_PEER     CTL_CODE(FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OVPN_IOCTL_GET_STATS    CTL_CODE(FILE_DEVICE_UNKNOWN, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OVPN_IOCTL_NEW_KEY      CTL_CODE(FILE_DEVICE_UNKNOWN, 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OVPN_IOCTL_SWAP_KEYS    CTL_CODE(FILE_DEVICE_UNKNOWN, 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OVPN_IOCTL_SET_PEER     CTL_CODE(FILE_DEVICE_UNKNOWN, 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OVPN_IOCTL_START_VPN    CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OVPN_IOCTL_DEL_PEER     CTL_CODE(FILE_DEVICE_UNKNOWN, 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OVPN_IOCTL_GET_VERSION  CTL_CODE(FILE_DEVICE_UNKNOWN, 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
