/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
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
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef TEST_PROBE_H
#define TEST_PROBE_H

void test_probe_request_roundtrip(void **state);

void test_probe_request_wire_format(void **state);

void test_probe_reply_roundtrip(void **state);

void test_probe_reply_wire_format(void **state);

void test_probe_request_forward_compat(void **state);

void test_probe_request_too_short(void **state);

void test_probe_reply_too_short(void **state);

void test_probe_reply_flags_contradict(void **state);

void test_find_tlv_value_truncated(void **state);

void test_find_tlv_trailing_bytes(void **state);

void test_find_tlv_skips_optional_after_wanted(void **state);

void test_find_tlv_rejects_unknown_mandatory(void **state);

void test_find_tlv_rejects_duplicate(void **state);

void test_find_tlv_empty_payload(void **state);

#endif
