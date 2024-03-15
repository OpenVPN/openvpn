/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2021 Fox Crypto B.V. <openvpn@foxcrypto.com>
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
 * @file Data Channel Cryptography Module
 *
 * @addtogroup data_crypto Data Channel Crypto module
 *
 * @par Crypto packet formats
 * The Data Channel Crypto module supports a number of crypto modes and
 * configurable options. The actual packet format depends on these options. A
 * Data Channel packet can consist of:
 *  - \b Opcode, one byte specifying the packet type (see @ref network_protocol
 *    "Network protocol").
 *  - \b Peer-id, if using the v2 data channel packet format (see @ref
 *    network_protocol "Network protocol").
 *  - \b HMAC, covering the ciphertext IV + ciphertext. The HMAC size depends
 *    on the \c \-\-auth option. If \c \-\-auth \c none is specified, there is no
 *    HMAC at all.
 *  - \b Ciphertext \b IV. The IV size depends on the \c \-\-cipher option.
 *  - \b Packet \b ID, a 32-bit incrementing packet counter that provides replay
 *    protection.
 *  - \b Timestamp, a 32-bit timestamp of the current time.
 *  - \b Payload, the plain text network packet to be encrypted (unless
 *    encryption is disabled by using \c \-\-cipher \c none). The payload might
 *    already be compressed (see @ref compression "Compression module").
 *
 * @par
 * This section does not discuss the opcode and peer-id, since those do not
 * depend on the data channel crypto. See @ref network_protocol
 * "Network protocol" for more information on those.
 *
 * @par
 * \e Legenda \n
 * <tt>[ xxx ]</tt> = unprotected \n
 * <tt>[ - xxx - ]</tt> = authenticated \n
 * <tt>[ * xxx * ]</tt> = encrypted and authenticated
 *
 * @par
 * <b>CBC data channel cypto format</b> \n
 * In CBC mode, both TLS-mode and static key mode are supported. The IV
 * consists of random bits to provide unpredictable IVs. \n
 * <i>CBC IV format:</i> \n
 * <tt> [ - random - ] </tt> \n
 * <i>CBC data channel crypto format in TLS-mode:</i> \n
 * <tt> [ HMAC ] [ - IV - ] [ * packet ID * ] [ * packet payload * ] </tt> \n
 * <i>CBC data channel crypto format in static key mode:</i> \n
 * <tt> [ HMAC ] [ - IV - ] [ * packet ID * ] [ * timestamp * ]
 * [ * packet payload * ] </tt>
 *
 * @par
 * <b>CFB/OFB data channel crypto format</b> \n
 * CFB and OFB modes are only supported in TLS mode. In these modes, the IV
 * consists of the packet counter and a timestamp. If the IV is more than 8
 * bytes long, the remaining space is filled with zeroes. The packet counter may
 * not roll over within a single TLS sessions. This results in a unique IV for
 * each packet, as required by the CFB and OFB cipher modes.
 *
 * @par
 * <i>CFB/OFB IV format:</i> \n
 * <tt>   [ - packet ID - ] [ - timestamp - ] [ - opt: zero-padding - ] </tt>\n
 * <i>CFB/OFB data channel crypto format:</i> \n
 * <tt>   [ HMAC ] [ - IV - ] [ * packet payload * ] </tt>
 *
 * @par
 * <b>GCM data channel crypto format</b> \n
 * GCM modes are only supported in TLS mode.  In these modes, the IV consists of
 * the 32-bit packet counter followed by data from the HMAC key.  The HMAC key
 * can be used as IV, since in GCM and CCM modes the HMAC key is not used for
 * the HMAC.  The packet counter may not roll over within a single TLS sessions.
 * This results in a unique IV for each packet, as required by GCM.
 *
 * @par
 * The HMAC key data is pre-shared during the connection setup, and thus can be
 * omitted in on-the-wire packets, saving 8 bytes per packet (for GCM and CCM).
 *
 * @par
 * In GCM mode, P_DATA_V2 headers (the opcode and peer-id) are also
 * authenticated as Additional Data.
 *
 * @par
 * <i>GCM IV format:</i> \n
 * <tt>   [ - packet ID - ] [ - HMAC key data - ] </tt>\n
 * <i>P_DATA_V1 GCM data channel crypto format:</i> \n
 * <tt>   [ opcode ] [ - packet ID - ] [ TAG ] [ * packet payload * ] </tt>
 * <i>P_DATA_V2 GCM data channel crypto format:</i> \n
 * <tt>   [ - opcode/peer-id - ] [ - packet ID - ] [ TAG ] [ * packet payload * ] </tt>
 *
 * @par
 * <b>No-crypto data channel format</b> \n
 * In no-crypto mode (\c \-\-cipher \c none is specified), both TLS-mode and
 * static key mode are supported. No encryption will be performed on the packet,
 * but packets can still be authenticated. This mode does not require an IV.\n
 * <i>No-crypto data channel crypto format in TLS-mode:</i> \n
 * <tt> [ HMAC ] [ - packet ID - ] [ - packet payload - ] </tt> \n
 * <i>No-crypto data channel crypto format in static key mode:</i> \n
 * <tt> [ HMAC ] [ - packet ID - ] [ - timestamp - ] [ - packet payload - ] </tt>
 *
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include "crypto_backend.h"
#include "basic.h"
#include "buffer.h"
#include "packet_id.h"
#include "mtu.h"

/** Wrapper struct to pass around SHA256 digests */
struct sha256_digest {
    uint8_t digest[SHA256_DIGEST_LENGTH];
};

/*
 * Defines a key type and key length for both cipher and HMAC.
 */
struct key_type
{
    const char *cipher;         /**< const name of the cipher */
    const char *digest;         /**< Message digest static parameters */
};

/**
 * Container for unidirectional cipher and HMAC %key material.
 * @ingroup control_processor
 */
struct key
{
    uint8_t cipher[MAX_CIPHER_KEY_LENGTH];
    /**< %Key material for cipher operations. */
    uint8_t hmac[MAX_HMAC_KEY_LENGTH];
    /**< %Key material for HMAC operations. */
};


/**
 * Container for one set of cipher and/or HMAC contexts.
 * @ingroup control_processor
 */
struct key_ctx
{
    cipher_ctx_t *cipher;       /**< Generic cipher %context. */
    hmac_ctx_t *hmac;           /**< Generic HMAC %context. */
    uint8_t implicit_iv[OPENVPN_MAX_IV_LENGTH];
    /**< The implicit part of the IV */
    size_t implicit_iv_len;     /**< The length of implicit_iv */
};

#define KEY_DIRECTION_BIDIRECTIONAL 0 /* same keys for both directions */
#define KEY_DIRECTION_NORMAL        1 /* encrypt with keys[0], decrypt with keys[1] */
#define KEY_DIRECTION_INVERSE       2 /* encrypt with keys[1], decrypt with keys[0] */

/**
 * Container for bidirectional cipher and HMAC %key material.
 * @ingroup control_processor
 */
struct key2
{
    int n;                      /**< The number of \c key objects stored
                                 *   in the \c key2.keys array. */
    struct key keys[2];         /**< Two unidirectional sets of %key
                                 *   material. */
};

/**
 * %Key ordering of the \c key2.keys array.
 * @ingroup control_processor
 *
 * This structure takes care of correct ordering when using unidirectional
 * or bidirectional %key material, and allows the same shared secret %key
 * file to be loaded in the same way by client and server by having one of
 * the hosts use an reversed ordering.
 */
struct key_direction_state
{
    int out_key;                /**< Index into the \c key2.keys array for
                                 *   the sending direction. */
    int in_key;                 /**< Index into the \c key2.keys array for
                                 *   the receiving direction. */
    int need_keys;              /**< The number of key objects necessary
                                 *   to support both sending and
                                 *   receiving.
                                 *
                                 *   This will be 1 if the same keys are
                                 *   used in both directions, or 2 if
                                 *   there are two sets of unidirectional
                                 *   keys. */
};

/**
 * Container for two sets of OpenSSL cipher and/or HMAC contexts for both
 * sending and receiving directions.
 * @ingroup control_processor
 */
struct key_ctx_bi
{
    struct key_ctx encrypt;     /**< Cipher and/or HMAC contexts for sending
                                 *   direction. */
    struct key_ctx decrypt;     /**< cipher and/or HMAC contexts for
                                 *   receiving direction. */
    bool initialized;
};

/**
 * Security parameter state for processing data channel packets.
 * @ingroup data_crypto
 */
struct crypto_options
{
    struct key_ctx_bi key_ctx_bi;
    /**< OpenSSL cipher and HMAC contexts for
     *   both sending and receiving
     *   directions. */
    struct packet_id packet_id; /**< Current packet ID state for both
                                 *   sending and receiving directions.
                                 *
                                 *   This contains the packet id that is
                                 *   used for replay protection.
                                 *
                                 *   The packet id also used as the IV
                                 *   for AEAD/OFB/CFG ciphers.
                                 *   */
    struct packet_id_persist *pid_persist;
    /**< Persistent packet ID state for
     *   keeping state between successive
     *   OpenVPN process startups. */

#define CO_PACKET_ID_LONG_FORM  (1<<0)
    /**< Bit-flag indicating whether to use
    *   OpenVPN's long packet ID format. */
#define CO_IGNORE_PACKET_ID     (1<<1)
    /**< Bit-flag indicating whether to ignore
     *   the packet ID of a received packet.
     *   This flag is used during processing
     *   of the first packet received from a
     *   client. */
#define CO_MUTE_REPLAY_WARNINGS (1<<2)
    /**< Bit-flag indicating not to display
     *   replay warnings. */
#define CO_USE_TLS_KEY_MATERIAL_EXPORT  (1<<3)
    /**< Bit-flag indicating that data channel key derivation
     * is done using TLS keying material export [RFC5705]
     */
#define CO_RESEND_WKC (1<<4)
    /**< Bit-flag indicating that the client is expected to
     * resend the wrapped client key with the 2nd packet (packet-id 1)
     * like with the HARD_RESET_CLIENT_V3 packet */
#define CO_FORCE_TLSCRYPTV2_COOKIE  (1<<5)
    /**< Bit-flag indicating that we do not allow clients that do
     * not support resending the wrapped client key (WKc) with the
     * third packet of the three-way handshake */
#define CO_USE_CC_EXIT_NOTIFY       (1<<6)
    /**< Bit-flag indicating that explicit exit notifies should be
     * sent via the control channel instead of using an OCC message
     */
#define CO_USE_DYNAMIC_TLS_CRYPT   (1<<7)
    /**< Bit-flag indicating that renegotiations are using tls-crypt
     *   with a TLS-EKM derived key.
     */

    unsigned int flags;         /**< Bit-flags determining behavior of
                                 *   security operation functions. */
};

#define CRYPT_ERROR(format) \
    do { msg(D_CRYPT_ERRORS, "%s: " format, error_prefix); goto error_exit; } while (false)

/**
 * Minimal IV length for AEAD mode ciphers (in bytes):
 * 4-byte packet id + 8 bytes implicit IV.
 */
#define OPENVPN_AEAD_MIN_IV_LEN (sizeof(packet_id_type) + 8)

#define RKF_MUST_SUCCEED (1<<0)
#define RKF_INLINE       (1<<1)
void read_key_file(struct key2 *key2, const char *file, const unsigned int flags);

/**
 * Write nkeys 1024-bits keys to file.
 *
 * @returns number of random bits written, or -1 on failure.
 */
int write_key_file(const int nkeys, const char *filename);

bool check_key(struct key *key, const struct key_type *kt);

bool write_key(const struct key *key, const struct key_type *kt,
               struct buffer *buf);

int read_key(struct key *key, const struct key_type *kt, struct buffer *buf);

/**
 * Initialize a key_type structure with.
 *
 * @param kt          The struct key_type to initialize
 * @param ciphername  The name of the cipher to use
 * @param authname    The name of the HMAC digest to use
 * @param tls_mode    Specifies whether we are running in TLS mode, which allows
 *                    more ciphers than static key mode.
 * @param warn        Print warnings when null cipher / auth is used.
 */
void init_key_type(struct key_type *kt, const char *ciphername,
                   const char *authname, bool tls_mode, bool warn);

/*
 * Key context functions
 */

void init_key_ctx(struct key_ctx *ctx, const struct key *key,
                  const struct key_type *kt, int enc,
                  const char *prefix);

void free_key_ctx(struct key_ctx *ctx);

void init_key_ctx_bi(struct key_ctx_bi *ctx, const struct key2 *key2,
                     int key_direction, const struct key_type *kt,
                     const char *name);

void free_key_ctx_bi(struct key_ctx_bi *ctx);


/**************************************************************************/
/** @name Functions for performing security operations on data channel packets
 *  @{ */

/**
 * Encrypt and HMAC sign a packet so that it can be sent as a data channel
 * VPN tunnel packet to a remote OpenVPN peer.
 * @ingroup data_crypto
 *
 * This function handles encryption and HMAC signing of a data channel
 * packet before it is sent to its remote OpenVPN peer.  It receives the
 * necessary security parameters in the \a opt argument, which should have
 * been set to the correct values by the \c tls_pre_encrypt() function.
 *
 * This function calls the \c EVP_Cipher* and \c HMAC_* functions of the
 * OpenSSL library to perform the actual security operations.
 *
 * If an error occurs during processing, then the \a buf %buffer is set to
 * empty.
 *
 * @param buf          - The %buffer containing the packet on which to
 *                       perform security operations.
 * @param work         - An initialized working %buffer.
 * @param opt          - The security parameter state for this VPN tunnel.
 *
 * @return This function returns void.\n On return, the \a buf argument
 *     will point to the resulting %buffer.  This %buffer will either
 *     contain the processed packet ready for sending, or be empty if an
 *     error occurred.
 */
void openvpn_encrypt(struct buffer *buf, struct buffer work,
                     struct crypto_options *opt);


/**
 * HMAC verify and decrypt a data channel packet received from a remote
 * OpenVPN peer.
 * @ingroup data_crypto
 *
 * This function handles authenticating and decrypting a data channel
 * packet received from a remote OpenVPN peer.  It receives the necessary
 * security parameters in the \a opt argument, which should have been set
 * to the correct values by the \c tls_pre_decrypt() function.
 *
 * This function calls the \c EVP_Cipher* and \c HMAC_* functions of the
 * OpenSSL library to perform the actual security operations.
 *
 * If an error occurs during processing, then the \a buf %buffer is set to
 * empty.
 *
 * @param buf          - The %buffer containing the packet received from a
 *                       remote OpenVPN peer on which to perform security
 *                       operations.
 * @param work         - A working %buffer.
 * @param opt          - The security parameter state for this VPN tunnel.
 * @param frame        - The packet geometry parameters for this VPN
 *                       tunnel.
 * @param ad_start     - A pointer into buf, indicating from where to start
 *                       authenticating additional data (AEAD mode only).
 *
 * @return
 * @li True, if the packet was authenticated and decrypted successfully.
 * @li False, if an error occurred. \n On return, the \a buf argument will
 *     point to the resulting %buffer.  This %buffer will either contain
 *     the plaintext packet ready for further processing, or be empty if
 *     an error occurred.
 */
bool openvpn_decrypt(struct buffer *buf, struct buffer work,
                     struct crypto_options *opt, const struct frame *frame,
                     const uint8_t *ad_start);

/** @} name Functions for performing security operations on data channel packets */

/**
 * Check packet ID for replay, and perform replay administration.
 *
 * @param opt   Crypto options for this packet, contains replay state.
 * @param pin   Packet ID read from packet.
 * @param error_prefix  Prefix to use when printing error messages.
 * @param gc    Garbage collector to use.
 *
 * @return true if packet ID is validated to be not a replay, false otherwise.
 */
bool crypto_check_replay(struct crypto_options *opt,
                         const struct packet_id_net *pin, const char *error_prefix,
                         struct gc_arena *gc);


/** Calculate the maximum overhead that our encryption has
 * on a packet. This does not include needed additional buffer size
 *
 * This does NOT include the padding and rounding of CBC size
 * as the users (mssfix/fragment) of this function need to adjust for
 * this and add it themselves.
 *
 * @param kt            Struct with the crypto algorithm to use
 * @param packet_id_size Size of the packet id
 * @param occ           if true calculates the overhead for crypto in the same
 *                      incorrect way as all previous OpenVPN versions did, to
 *                      end up with identical numbers for OCC compatibility
 */
unsigned int
calculate_crypto_overhead(const struct key_type *kt,
                          unsigned int pkt_id_size,
                          bool occ);

/** Return the worst-case OpenVPN crypto overhead (in bytes) */
unsigned int crypto_max_overhead(void);

/**
 * Generate a server key with enough randomness to fill a key struct
 * and write to file.
 *
 * @param filename          Filename of the server key file to create.
 * @param pem_name          The name to use in the PEM header/footer.
 */
void
write_pem_key_file(const char *filename, const char *key_name);

/**
 * Generate ephermal key material into the key structure
 *
 * @param key           the key structure that will hold the key material
 * @param pem_name      the name used for logging
 * @return              true if key generation was successful
 */
bool
generate_ephemeral_key(struct buffer *key, const char *pem_name);

/**
 * Read key material from a PEM encoded files into the key structure
 * @param key           the key structure that will hold the key material
 * @param pem_name      the name used in the pem encoding start/end lines
 * @param key_file      name of the file to read or the key itself if
 *                      key_inline is true
 * @param key_inline    True if key_file contains an inline key, False
 *                      otherwise.
 * @return              true if reading into key was successful
 */
bool
read_pem_key_file(struct buffer *key, const char *pem_name,
                  const char *key_file, bool key_inline);

/*
 * Message digest-based pseudo random number generator.
 *
 * If the PRNG was initialised with a certain message digest, uses the digest
 * to calculate the next random number, and prevent depletion of the entropy
 * pool.
 *
 * This PRNG is aimed at IV generation and similar miscellaneous tasks. Use
 * \c rand_bytes() for higher-assurance functionality.
 *
 * Retrieves len bytes of pseudo random data, and places it in output.
 *
 * @param output        Output buffer
 * @param len           Length of the output buffer
 */
void prng_bytes(uint8_t *output, int len);

/* an analogue to the random() function, but use prng_bytes */
long int get_random(void);

/** Print a cipher list entry */
void print_cipher(const char *cipher);

void test_crypto(struct crypto_options *co, struct frame *f);


/* key direction functions */

void key_direction_state_init(struct key_direction_state *kds, int key_direction);

void verify_fix_key2(struct key2 *key2, const struct key_type *kt, const char *shared_secret_file);

void must_have_n_keys(const char *filename, const char *option, const struct key2 *key2, int n);

int ascii2keydirection(int msglevel, const char *str);

const char *keydirection2ascii(int kd, bool remote, bool humanreadable);

/* print keys */
void key2_print(const struct key2 *k,
                const struct key_type *kt,
                const char *prefix0,
                const char *prefix1);

void crypto_read_openvpn_key(const struct key_type *key_type,
                             struct key_ctx_bi *ctx, const char *key_file,
                             bool key_inline, const int key_direction,
                             const char *key_name, const char *opt_name,
                             struct key2 *keydata);

/*
 * Inline functions
 */

/**
 * As memcmp(), but constant-time.
 * Returns 0 when data is equal, non-zero otherwise.
 */
int memcmp_constant_time(const void *a, const void *b, size_t size);

static inline bool
key_ctx_bi_defined(const struct key_ctx_bi *key)
{
    return key->encrypt.cipher || key->encrypt.hmac || key->decrypt.cipher || key->decrypt.hmac;
}

/**
 * To be used when printing a string that may contain inline data.
 *
 * If "is_inline" is true, return the inline tag.
 * If "is_inline" is false and "str" is not NULL, return "str".
 * Return the constant string "[NULL]" otherwise.
 *
 * @param str       the original string to return when is_inline is false
 * @param is_inline true when str contains an inline data of some sort
 */
const char *print_key_filename(const char *str, bool is_inline);

/**
 * Creates and validates an instance of struct key_type with the provided
 * algs.
 *
 * @param cipher    the cipher algorithm to use (must be a string literal)
 * @param md        the digest algorithm to use (must be a string literal)
 * @param optname   the name of the option requiring the key_type object
 *
 * @return          the initialized key_type instance
 */
static inline struct key_type
create_kt(const char *cipher, const char *md, const char *optname)
{
    struct key_type kt;
    kt.cipher = cipher;
    kt.digest = md;

    if (cipher_defined(kt.cipher) && !cipher_valid(kt.cipher))
    {
        msg(M_WARN, "ERROR: --%s requires %s support.", optname, kt.cipher);
        return (struct key_type) { 0 };
    }
    if (md_defined(kt.digest) && !md_valid(kt.digest))
    {
        msg(M_WARN, "ERROR: --%s requires %s support.", optname, kt.digest);
        return (struct key_type) { 0 };
    }

    return kt;
}

/**
 * Checks if the current TLS library supports the TLS 1.0 PRF with MD5+SHA1
 * that OpenVPN uses when TLS Keying Material Export is not available.
 *
 * @return  true if supported, false otherwise.
 */
bool check_tls_prf_working(void);

#endif /* CRYPTO_H */
