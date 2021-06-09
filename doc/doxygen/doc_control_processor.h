/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2010-2021 Fox Crypto B.V. <openvpn@fox-it.com>
 *
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

/**
 * @file
 * Control Channel Processor module documentation file.
 */

/**
 * @defgroup control_processor Control Channel Processor module
 *
 * This module controls the setup and maintenance of VPN tunnels and the
 * associated security parameters.
 *
 * @par This module's role
 * The Control Channel Processor module lies at the core of OpenVPN's
 * activities.  It handles the setup of new VPN tunnels, the negotiation
 * of data channel security parameters, the managing of active VPN
 * tunnels, and finally the cleanup of expired VPN tunnels.
 *
 * @par State structures
 * A large amount of VPN tunnel state information must be stored within an
 * OpenVPN process.  A wide variety of container structures are used by
 * this module for that purpose.  Several of these structures are listed
 * below, and the function of the first three VPN tunnel state containers
 * is described in more detail later.
 *  - VPN tunnel state containers:
 *     - \c tls_multi, security parameter state for a single VPN tunnel.
 *       Contains three instances of the \c tls_session structure.
 *     - \c tls_session, security parameter state of a single session
 *       within a VPN tunnel.  Contains two instances of the \c key_state
 *       structure.
 *     - \c key_state, security parameter state of one TLS and data
 *       channel %key set.
 *  - Data channel security parameter containers:
 *     - \c key_ctx_bi, container for two sets of OpenSSL cipher and/or
 *       HMAC context (both directions).  Contains two instances of the \c
 *       key_ctx structure.
 *     - \c key_ctx, container for one set of OpenSSL cipher and/or HMAC
 *       context (one directions.
 *  - Key material containers:
 *     - \c key2, container for two sets of cipher and/or HMAC %key
 *       material (both directions).  Contains two instances of the \c key
 *       structure.
 *     - \c key, container for one set of cipher and/or HMAC %key material
 *       (one direction).
 *     - \c key_direction_state, ordering of %key material within the \c
 *       key2.key array.
 *  - Key method 2 random material containers:
 *     - \c key_source2, container for both halves of random material used
 *       for %key method 2.  Contains two instances of the \c key_source
 *       structure.
 *     - \c key_source, container for one half of random material used for
 *       %key method 2.
 *
 * @par The life of a \c tls_multi object
 * A \c tls_multi structure contains all the security parameter state
 * information related to the control and data channels of one VPN tunnel.
 * Its life cycle can be summarized as follows:
 *  -# Initialization: \c tls_multi_init() and \c
 *     tls_multi_init_finalize(), which are called (indirectly) from \c
 *     init_instance() when initializing a new \c context structure.
 *     - Initializes a \c tls_multi structure.
 *     - Allocates the three \c tls_session objects contained by the \c
 *       tls_multi structure, and initializes as appropriate.
 *  -# Management: \c tls_multi_process() and \c tls_pre_decrypt()
 *     - If a new session is initiated by the remote peer, then \c
 *       tls_pre_decrypt() starts the new session negotiation in the
 *       un-trusted \c tls_session.
 *     - If the, as yet, un-trusted \c tls_session authenticates
 *       successfully, then \c tls_multi_process() moves it so as to be
 *       the active \c tls_session.
 *     - If an error occurs during processing of a \c key_state object,
 *       then \c tls_multi_process() cleans up and initializes the
 *       associated \c tls_session object.  If the error occurred in the
 *       active \c key_state of the active \c tls_session and the
 *       lame-duck \c key_state of that \c tls_session has not yet
 *       expired, it is preserved as fallback.
 *  -# Cleanup: \c tls_multi_free(), which is called (indirectly) from \c
 *     close_instance() when cleaning up a \c context structure.
 *     - Cleans up a \c tls_multi structure.
 *     - Cleans up the three \c tls_session objects contained by the \c
 *       tls_multi structure.
 *
 * @par The life of a \c tls_session object
 * A \c tls_session structure contains the state information related to an
 * active and a lame-duck \c key_state.  Its life cycle can be summarized
 * as follows:
 *  -# Initialization: \c tls_session_init()
 *     - Initializes a \c tls_session structure.
 *     - Initializes the primary \c key_state by calling \c
 *       key_state_init().
 *  -# Renegotiation: \c key_state_soft_reset()
 *     - Cleans up the old lame-duck \c key_state by calling \c
 *       key_state_free().
 *     - Moves the old primary \c key_state to be the new lame-duck \c
 *       key_state.
 *     - Initializes a new primary \c key_state by calling \c
 *       key_state_init().
 *  -# Cleanup: \c tls_session_free()
 *     - Cleans up a \c tls_session structure.
 *     - Cleans up all \c key_state objects associated with the session by
 *       calling \c key_state_free() for each.
 *
 * @par The life of a \c key_state object
 * A \c key_state structure represents one control and data channel %key
 * set.  It contains an OpenSSL TLS object that encapsulates the control
 * channel, and the data channel security parameters needed by the \link
 * data_crypto Data Channel Crypto module\endlink to perform cryptographic
 * operations on data channel packets.  Its life cycle can be summarized
 * as follows:
 *  -# Initialization: \c key_state_init()
 *     - Initializes a \c key_state structure.
 *     - Creates a new OpenSSL TLS object to encapsulate this new control
 *       channel session.
 *     - Sets \c key_state.state to \c S_INITIAL.
 *     - Allocates several internal buffers.
 *     - Initializes new reliability layer structures for this key set.
 *  -# Negotiation: \c tls_process()
 *     - The OpenSSL TLS object negotiates a TLS session between itself
 *       and the remote peer's TLS object.
 *     - Key material is generated and exchanged through the TLS session
 *       between OpenVPN peers.
 *     - Both peers initialize their data channel cipher and HMAC key
 *       contexts.
 *     - On successful negotiation, the \c key_state.state will progress
 *       from \c S_INITIAL to \c S_ACTIVE and \c S_NORMAL.
 *  -# Active tunneling: \link data_crypto Data Channel Crypto
 *     module\endlink
 *     - Data channel packet to be sent to a remote OpenVPN peer:
 *        - \c tls_pre_encrypt() loads the security parameters from the \c
 *          key_state into a \c crypto_options structure.
 *        - \c openvpn_encrypt() uses the \c crypto_options to an encrypt
 *          and HMAC sign the data channel packet.
 *     - Data channel packet received from a remote OpenVPN peer:
 *        - \c tls_pre_decrypt() loads the security parameters from the \c
 *          key_state into a \c crypto_options structure.
 *        - \c openvpn_encrypt() uses the \c crypto_options to
 *          authenticate and decrypt the data channel packet.
 *  -# Cleanup: \c key_state_free()
 *     - Cleans up a \c key_state structure together with its OpenSSL TLS
 *       object, key material, internal buffers, and reliability layer
 *       structures.
 *
 * @par Control functions
 * The following two functions drive the Control Channel Processor's
 * activities.
 *  - \c tls_multi_process(), iterates through the \c tls_session objects
 *    within a given \c tls_multi of a VPN tunnel, and calls \c
 *    tls_process() for each \c tls_session which is being set up, is
 *    already active, or is busy expiring.
 *  - \c tls_process(), performs the Control Channel Processor module's
 *    core handling of received control channel messages, and generates
 *    appropriate messages to be sent.
 *
 * @par Functions which control data channel key generation
 *  - Key method 1 key exchange functions were removed from OpenVPN 2.5
 *  - Key method 2 key exchange functions:
 *     - \c key_method_2_write(), generates and processes key material to
 *       be sent to the remote OpenVPN peer.
 *     - \c key_method_2_read(), processes key material received from the
 *       remote OpenVPN peer.
 */
