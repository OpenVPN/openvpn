/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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

/**
 * @file
 * @brief Buffer management functions and garbage collection.
 *
 * This module provides the core \c buffer type used throughout OpenVPN to
 * hold packet data, as well as a simple memory management system
 * (\c gc_arena / \c gc_malloc()) and various string/memory utility functions.
 */

#ifndef BUFFER_H
#define BUFFER_H

#include "basic.h"
#include "error.h"
#include "integer.h"

/** Maximum allowed size (in bytes) for a single buffer allocation. */
#define BUF_SIZE_MAX 1000000

/*
 * Define verify_align function, otherwise
 * it will be a noop.
 */
/* #define VERIFY_ALIGNMENT */

/*
 * Keep track of source file/line of buf_init calls
 */
#ifdef VERIFY_ALIGNMENT
#define BUF_INIT_TRACKING
#endif

/**************************************************************************/
/**
 * Wrapper structure for dynamically allocated memory.
 *
 * The actual content stored in a \c buffer structure starts at the memory
 * location \c buffer.data \c + \c buffer.offset, and has a length of \c
 * buffer.len bytes.  This, together with the space available before and
 * after the content, is represented in the pseudocode below:
 * @code
 * uint8_t *content_start    = buffer.data + buffer.offset;
 * uint8_t *content_end      = buffer.data + buffer.offset + buffer.len;
 * int      prepend_capacity = buffer.offset;
 * int      append_capacity  = buffer.capacity - (buffer.offset + buffer.len);
 * @endcode
 */
struct buffer
{
    int capacity;  /**< Size in bytes of memory allocated by
                    *   \c malloc(). */
    int offset;    /**< Offset in bytes of the actual content
                    *   within the allocated memory. */
    int len;       /**< Length in bytes of the actual content
                    *   within the allocated memory. */
    uint8_t *data; /**< Pointer to the allocated memory. */

#ifdef BUF_INIT_TRACKING
    const char *debug_file;
    int debug_line;
#endif
};


/**************************************************************************/
/**
 * Garbage collection entry for one dynamically allocated block of memory.
 *
 * This structure represents one link in the linked list contained in a \c
 * gc_arena structure.  Each time the \c gc_malloc() function is called,
 * it allocates \c sizeof(gc_entry) + the requested number of bytes.  The
 * \c gc_entry is then stored as a header in front of the memory address
 * returned to the caller.
 */
struct gc_entry
{
    struct gc_entry *next; /**< Pointer to the next item in the
                            *   linked list. */
};

/**
 * Garbage collection entry for a specially allocated structure that needs
 * a custom free function to be freed like struct addrinfo
 *
 */
struct gc_entry_special
{
    struct gc_entry_special *next;
    void (*free_fnc)(void *);
    void *addr;
};


/**
 * Garbage collection arena used to keep track of dynamically allocated
 * memory.
 *
 * This structure contains a linked list of \c gc_entry structures.  When
 * a block of memory is allocated using the \c gc_malloc() function, the
 * allocation is registered in the function's \c gc_arena argument.  All
 * the dynamically allocated memory registered in a \c gc_arena can be
 * freed using the \c gc_free() function.
 */
struct gc_arena
{
    struct gc_entry *list;                 /**< First element of the linked list of
                                            *   \c gc_entry structures. */
    struct gc_entry_special *list_special; /**< First element of the linked
                                            *   list of \c gc_entry_special
                                            *   structures for allocations
                                            *   requiring a custom free
                                            *   function. */
};


/** Return a pointer to the start of the buffer content. @see buf_bptr() */
#define BPTR(buf)  (buf_bptr(buf))
/** Return a pointer one past the end of the buffer content. @see buf_bend() */
#define BEND(buf)  (buf_bend(buf))
/** Return a pointer to the last byte of the buffer content, or NULL if empty. @see buf_blast() */
#define BLAST(buf) (buf_blast(buf))
/** Return the length of the buffer content in bytes. @see buf_len() */
#define BLEN(buf)  (buf_len(buf))
/** Return the length of the buffer content as a \c size_t. @see buf_len() */
#define BLENZ(buf) ((size_t)buf_len(buf))
/** Return true iff the buffer is defined (has non-NULL data pointer). @see buf_defined() */
#define BDEF(buf)  (buf_defined(buf))
/** Return the buffer content pointer cast to \c char *. @see buf_str() */
#define BSTR(buf)  (buf_str(buf))
/** Return the number of bytes available for appending to the buffer. @see buf_forward_capacity() */
#define BCAP(buf)  (buf_forward_capacity(buf))

/**
 * Zeroise and reset a buffer.
 *
 * Sets all allocated memory to zero and resets \c offset and \c len to zero,
 * but does not free the underlying memory.
 *
 * @param buf   The buffer to clear.
 */
void buf_clear(struct buffer *buf);

/**
 * Free the memory allocated for a buffer.
 *
 * Frees \c buf->data and resets the buffer to an undefined state.
 *
 * @param buf   The buffer whose memory is to be freed.
 */
void free_buf(struct buffer *buf);

/**
 * Assign the content of one buffer to another.
 *
 * Copies the content of \c src into \c dest.  The destination buffer must
 * already be allocated with sufficient capacity.
 *
 * @param dest  Destination buffer to write into.
 * @param src   Source buffer to read from.
 *
 * @return true on success, false if \c dest has insufficient capacity.
 */
bool buf_assign(struct buffer *dest, const struct buffer *src);

/**
 * Securely clear a null-terminated string.
 *
 * Overwrites all characters of \c str with zeroes.
 *
 * @param str   The string to clear.
 */
void string_clear(char *str);

/**
 * Return the number of elements in a NULL-terminated array of strings.
 *
 * @param array     NULL-terminated array of string pointers.
 *
 * @return Number of non-NULL elements.
 */
int string_array_len(const char **array);

/**
 * Safely compute the product of two sizes plus an extra amount.
 *
 * Each of \c m1, \c m2, and \c extra, as well as the final result, are
 * checked against \c ALLOC_SIZE_MAX.  If any value exceeds the limit the
 * function calls \c msg(M_FATAL) and does not return.
 *
 * @param m1    First multiplicand.
 * @param m2    Second multiplicand.
 * @param extra Value to add to the product.
 *
 * @return \c m1 * \c m2 + \c extra.
 */
size_t array_mult_safe(const size_t m1, const size_t m2, const size_t extra);

/** Flag for print_argv(): wrap each argument in square brackets. */
#define PA_BRACKET (1 << 0)
/**
 * Format a NULL-terminated argument vector as a single string.
 *
 * @param p     NULL-terminated array of string pointers to format.
 * @param gc    Garbage collection arena for the returned string.
 * @param flags Formatting flags (e.g. \c PA_BRACKET).
 *
 * @return Newly allocated string representation of \c p.
 */
char *print_argv(const char **p, struct gc_arena *gc, const unsigned int flags);

/**
 * Report a buffer size error and abort.
 *
 * Called when a requested buffer size exceeds \c BUF_SIZE_MAX or is otherwise
 * invalid.  Calls \c msg(M_FATAL) and does not return.
 *
 * @param size  The invalid size that was requested.
 */
void buf_size_error(const size_t size);

/**
 * Allocate a buffer of the given size.
 *
 * Calls \c out_of_memory() if the allocation fails. The caller is responsible
 * for freeing the memory.
 *
 * @param size  Number of bytes to allocate.
 *
 * @return Newly allocated buffer of capacity \c size.
 */
struct buffer alloc_buf(size_t size);

/**
 * Allocate a buffer of the given size under garbage collection.
 *
 * The allocated memory is registered with \c gc so that it is freed when
 * \c gc_free() is called on the arena.  Calls \c out_of_memory() if the
 * allocation fails.
 *
 * @param size  Number of bytes to allocate.
 * @param gc    Garbage collection arena to register the allocation with.
 *
 * @return Newly allocated buffer of capacity \c size.
 */
struct buffer alloc_buf_gc(size_t size, struct gc_arena *gc);

/**
 * Duplicate a buffer, including its content.
 *
 * Allocates a new buffer with the same capacity as \c buf and copies its
 * content.  Calls \c out_of_memory() if the allocation fails.
 *
 * @param buf   The buffer to duplicate.
 *
 * @return A newly allocated copy of \c buf.
 */
struct buffer clone_buf(const struct buffer *buf);

/**
 * Allocate memory and, optionally, zero it.
 *
 * The allocation is registered with \c a so that it is freed when
 * \c gc_free() is called on the arena.  Calls \c out_of_memory() if the
 * allocation fails.
 *
 * @param size  Number of bytes to allocate.
 * @param clear If true, zeroise the allocated memory before returning.
 * @param a     Garbage collection arena to register the allocation with.
 *
 * @return Pointer to the newly allocated memory.
 */
void *gc_malloc(size_t size, bool clear, struct gc_arena *a);

/**
 * Duplicate a string, allocating memory under garbage collection.
 *
 * @param str   The string to duplicate.  May be NULL, in which case NULL
 *              is returned.
 * @param gc    Garbage collection arena for the returned string, or NULL
 *              to use plain \c malloc().
 *
 * @return A newly allocated copy of \c str, or NULL if \c str is NULL.
 */
char *string_alloc(const char *str, struct gc_arena *gc);

/**
 * Allocate a buffer containing a copy of the given string.
 *
 * Wraps \c string_alloc(), so \c gc may be NULL (plain \c malloc() is used
 * in that case).  The buffer \c len reflects the string length, excluding
 * the null terminator, even though the terminator is present in the
 * allocated memory.
 *
 * @param str   The string to copy into the buffer.  Must not be NULL.
 * @param gc    Garbage collection arena for the allocation, or NULL.
 *
 * @return A buffer whose content is a copy of \c str.
 */
struct buffer string_alloc_buf(const char *str, struct gc_arena *gc);

/**
 * Register an address with a custom free function in a garbage collection
 * arena.
 *
 * When \c gc_free() is called on \c a, \c free_function(addr) will be
 * invoked to release the memory.  Use this for allocations that require
 * something other than plain \c free(), such as \c freeaddrinfo().
 *
 * @param addr          Pointer to the memory to register.
 * @param free_function Function to call to free \c addr.
 * @param a             Garbage collection arena to register with.
 */
void gc_addspecial(void *addr, void (*free_function)(void *), struct gc_arena *a);

/**
 * allows to realloc a pointer previously allocated by gc_malloc or gc_realloc
 *
 * @note only use this function on pointers returned by gc_malloc or re_alloc
 *       with the same gc_arena
 *
 * @param ptr   Pointer of the previously allocated memory
 * @param size  New size
 * @param a     gc_arena to use
 * @return      new pointer
 */
void *gc_realloc(void *ptr, size_t size, struct gc_arena *a);

#ifdef BUF_INIT_TRACKING
#define buf_init(buf, offset) buf_init_debug(buf, offset, __FILE__, __LINE__)
/** Debug variant of \c buf_init_dowork() that records the call site for alignment verification. */
bool buf_init_debug(struct buffer *buf, int offset, const char *file, int line);

#else
#define buf_init(buf, offset) buf_init_dowork(buf, offset)
#endif


/* inline functions */

/**
 * Callback to free a \c struct \c addrinfo, suitable for use with
 * \c gc_addspecial().
 *
 * @param addr  Pointer to the \c struct \c addrinfo to free.
 */
static inline void
gc_freeaddrinfo_callback(void *addr)
{
    freeaddrinfo((struct addrinfo *)addr);
}

/** Return an empty, undefined \c struct \c buffer (all fields zero). */
static inline struct buffer
clear_buf(void)
{
    return (struct buffer){ 0 };
}

/**
 * Return true iff \c buf has a non-NULL data pointer.
 *
 * A defined buffer has been allocated but may have zero length or negative
 * len (i.e. it is not necessarily valid).
 *
 * @param buf   The buffer to test.
 */
static inline bool
buf_defined(const struct buffer *buf)
{
    return buf->data != NULL;
}

/**
 * Return true iff \c buf is valid.
 *
 * A buffer is valid when its data pointer is non-NULL and its \c len is
 * non-negative.
 *
 * @param buf   The buffer to test.
 */
static inline bool
buf_valid(const struct buffer *buf)
{
    return likely(buf->data != NULL) && likely(buf->len >= 0);
}

/**
 * Return a pointer to the start of the buffer content.
 *
 * @param buf   The buffer to query.
 *
 * @return Pointer to \c buf->data + \c buf->offset, or NULL if \c buf is
 *         not valid.
 */
static inline uint8_t *
buf_bptr(const struct buffer *buf)
{
    if (buf_valid(buf))
    {
        return buf->data + buf->offset;
    }
    else
    {
        return NULL;
    }
}

/**
 * Return the length of the buffer content.
 *
 * @param buf   The buffer to query.
 *
 * @return \c buf->len if \c buf is valid, otherwise 0.
 */
static int
buf_len(const struct buffer *buf)
{
    if (buf_valid(buf))
    {
        return buf->len;
    }
    else
    {
        return 0;
    }
}

/**
 * Return a pointer one past the end of the buffer content.
 *
 * @param buf   The buffer to query.
 *
 * @return Pointer to the byte immediately after the last content byte.
 */
static inline uint8_t *
buf_bend(const struct buffer *buf)
{
    return buf_bptr(buf) + buf_len(buf);
}

/**
 * Return a pointer to the last byte of the buffer content.
 *
 * @param buf   The buffer to query.
 *
 * @return Pointer to the last byte, or NULL if the buffer is empty or
 *         invalid.
 */
static inline uint8_t *
buf_blast(const struct buffer *buf)
{
    if (buf_len(buf) > 0)
    {
        return buf_bptr(buf) + buf_len(buf) - 1;
    }
    else
    {
        return NULL;
    }
}

/**
 * Return true iff \c size is within the allowed buffer size range.
 *
 * @param size  The size to check.
 *
 * @return true if \c size < \c BUF_SIZE_MAX.
 */
static inline bool
buf_size_valid(const size_t size)
{
    return likely(size < BUF_SIZE_MAX);
}

/**
 * Return true iff a signed \c size is within the allowed buffer size range.
 *
 * Accepts negative values (used for bidirectional length adjustments) as
 * long as the absolute value is below \c BUF_SIZE_MAX.
 *
 * @param size  The signed size to check.
 *
 * @return true if \c -BUF_SIZE_MAX <= size < \c BUF_SIZE_MAX.
 */
static inline bool
buf_size_valid_signed(const int size)
{
    return likely(size >= -BUF_SIZE_MAX) && likely(size < BUF_SIZE_MAX);
}

/**
 * Return the buffer content pointer cast to \c char *.
 *
 * @param buf   The buffer to query.
 *
 * @return The content pointer as a \c char *, or NULL if \c buf is invalid.
 */
static inline char *
buf_str(const struct buffer *buf)
{
    return (char *)buf_bptr(buf);
}

/**
 * Reset a buffer to an undefined (unallocated) state.
 *
 * Sets all fields to zero/NULL without freeing any memory.  Use \c free_buf()
 * first if the buffer owns allocated memory.
 *
 * @param buf   The buffer to reset.
 */
static inline void
buf_reset(struct buffer *buf)
{
    buf->capacity = 0;
    buf->offset = 0;
    buf->len = 0;
    buf->data = NULL;
}

/**
 * Reset the length and offset of a buffer to zero.
 *
 * The underlying allocation is preserved and \c capacity is unchanged.
 * Equivalent to rewinding the buffer to the beginning for fresh writing.
 *
 * @param buf   The buffer to reset.
 */
static inline void
buf_reset_len(struct buffer *buf)
{
    buf->len = 0;
    buf->offset = 0;
}

/**
 * Initialise a buffer with a given initial offset.
 *
 * Sets \c buf->len to zero and \c buf->offset to \c offset.  The buffer must
 * already be allocated.  Returns false (without modifying \c buf) if \c offset
 * is negative, exceeds the buffer capacity, or the data pointer is NULL.
 *
 * @param buf     The buffer to initialise.
 * @param offset  Initial byte offset from the start of the allocated memory.
 *
 * @return true on success, false if the parameters are invalid.
 */
static inline bool
buf_init_dowork(struct buffer *buf, int offset)
{
    if (offset < 0 || offset > buf->capacity || buf->data == NULL)
    {
        return false;
    }
    buf->len = 0;
    buf->offset = offset;
    return true;
}

/**
 * Initialise a buffer with an externally provided writable memory region.
 *
 * Sets up \c buf to use \c data as its backing store for writing.  The first
 * byte of \c data is set to zero.  Calls \c buf_size_error() (which does not
 * return) if \c size exceeds \c BUF_SIZE_MAX.
 *
 * @param buf   The buffer to initialise.
 * @param data  Pointer to the memory region to use.
 * @param size  Size of the memory region in bytes.
 */
static inline void
buf_set_write(struct buffer *buf, uint8_t *data, int size)
{
    if (!buf_size_valid(size))
    {
        buf_size_error(size);
    }
    buf->len = 0;
    buf->offset = 0;
    buf->capacity = size;
    buf->data = data;
    if (size > 0 && data)
    {
        *data = 0;
    }
}

/**
 * Initialise a buffer with an externally provided read-only memory region.
 *
 * Sets up \c buf so that the entire \c data region is the buffer content
 * (offset is 0, len and capacity are both set to \c size).  The data pointer
 * is cast away from const.  Calls \c buf_size_error() (which does not return)
 * if \c size exceeds \c BUF_SIZE_MAX.
 *
 * @param buf   The buffer to initialise.
 * @param data  Pointer to the read-only memory region.
 * @param size  Size of the memory region in bytes.
 */
static inline void
buf_set_read(struct buffer *buf, const uint8_t *data, size_t size)
{
    if (!buf_size_valid(size))
    {
        buf_size_error(size);
    }
    buf->len = buf->capacity = (int)size;
    buf->offset = 0;
    buf->data = (uint8_t *)data;
}

/**
 * Like \c strncpy() but always null-terminates the destination.
 *
 * Copies at most \c maxlen - 1 characters from \c src into \c dest and
 * writes a null terminator at \c dest[\c maxlen - 1].  Does nothing if
 * \c maxlen is zero.
 *
 * @param dest    Destination buffer.
 * @param src     Source string.
 * @param maxlen  Size of the destination buffer in bytes.
 */
static inline void
strncpynt(char *dest, const char *src, size_t maxlen)
{
    if (maxlen > 0)
    {
        strncpy(dest, src, maxlen - 1);
        dest[maxlen - 1] = 0;
    }
}

/**
 * Return true if the string contains at least one decimal digit.
 *
 * @param src   The null-terminated string to scan.
 *
 * @return true if any character in \c src satisfies \c isdigit().
 */
static inline bool
has_digit(const char *src)
{
    char c;
    while ((c = *src++))
    {
        if (isdigit(c))
        {
            return true;
        }
    }
    return false;
}

/**
 * Securely zeroise memory.
 *
 * This code and description are based on code supplied by Zhaomo Yang, of the
 * University of California, San Diego (which was released into the public
 * domain).
 *
 * The secure_memzero function attempts to ensure that an optimizing compiler
 * does not remove the intended operation if cleared memory is not accessed
 * again by the program. This code has been tested under Clang 3.9.0 and GCC
 * 6.2 with optimization flags -O, -Os, -O0, -O1, -O2, and -O3 on
 * Ubuntu 16.04.1 LTS; under Clang 3.9.0 with optimization flags -O, -Os,
 * -O0, -O1, -O2, and -O3 on FreeBSD 10.2-RELEASE; under Microsoft Visual Studio
 * 2015 with optimization flags /O1, /O2 and /Ox on Windows 10.
 *
 * Theory of operation:
 *
 * 1. On Windows, use the SecureZeroMemory which ensures that data is
 *    overwritten.
 * 2. Under GCC or Clang, use a memory barrier, which forces the preceding
 *    memset to be carried out. The overhead of a memory barrier is usually
 *    negligible.
 * 3. If none of the above are available, use the volatile pointer
 *    technique to zero memory one byte at a time.
 *
 * @param data  Pointer to data to zeroise.
 * @param len   Length of data, in bytes.
 */
static inline void
secure_memzero(void *data, size_t len)
{
#if defined(_WIN32)
    SecureZeroMemory(data, len);
#elif defined(__GNUC__) || defined(__clang__)
    memset(data, 0, len);
    __asm__ __volatile__("" : : "r"(data) : "memory");
#else
    volatile char *p = (volatile char *)data;
    while (len--)
    {
        *p++ = 0;
    }
#endif
}

/**
 * printf-style append to a buffer with overflow check.
 *
 * Formats a string and appends it to \c buf.  Due to the use of
 * \c vsnprintf(), one byte of forward capacity is reserved for a null
 * terminator, so at most \c buf_forward_capacity(buf) - 1 bytes of
 * formatted output are written.
 *
 * @param buf     The buffer to append to.
 * @param format  printf-style format string.
 * @param ...     Format arguments.
 *
 * @return true if the entire formatted string fit in the buffer, false if
 *         it was truncated.
 */
bool buf_printf(struct buffer *buf, const char *format, ...)
#ifdef __GNUC__
#if __USE_MINGW_ANSI_STDIO
    __attribute__((format(gnu_printf, 2, 3)))
#else
    __attribute__((format(__printf__, 2, 3)))
#endif
#endif
    ;

/**
 * Append a string to a buffer with overflow check.
 *
 * @param buf   The buffer to append to.
 * @param str   The null-terminated string to append.
 *
 * @return true if the string fit in the buffer, false if it was truncated.
 */
bool buf_puts(struct buffer *buf, const char *str);


/*
 * remove/add trailing characters
 */

/**
 * Force a null terminator at the end of the buffer content.
 *
 * If there is free capacity, a '\\0' byte is appended.  If the buffer is
 * full, the last content byte is overwritten with '\\0' (i.e. the last
 * character is truncated to make room).  The function has no effect on an
 * empty or invalid buffer.
 *
 * @param buf   The buffer to null-terminate.
 */
void buf_null_terminate(struct buffer *buf);

/**
 * Remove trailing newline and carriage-return characters from a buffer.
 *
 * @param buf   The buffer to chomp.
 */
void buf_chomp(struct buffer *buf);

/**
 * Remove all occurrences of a specific byte from the end of a buffer.
 *
 * @param buf     The buffer to modify.
 * @param remove  The byte value to strip from the tail.
 */
void buf_rmtail(struct buffer *buf, uint8_t remove);

/** @name String Utility Functions
 *  @brief Non-buffer string functions
 */
/**@{*/

/**
 * Remove trailing newline and carriage-return characters from a string.
 *
 * @param str   The null-terminated string to chomp.
 */
void chomp(char *str);

/**
 * Remove all trailing characters that appear in a given set.
 *
 * @param str             The null-terminated string to modify in place.
 * @param what_to_delete  Null-terminated set of characters to strip.
 */
void rm_trailing_chars(char *str, const char *what_to_delete);

/**
 * Return a pointer past any leading whitespace in a string.
 *
 * @param str   The string to skip whitespace in.
 *
 * @return Pointer to the first non-whitespace character, or to the null
 *         terminator if \c str is all whitespace.
 */
const char *skip_leading_whitespace(const char *str);

/**
 * Null-terminate a fixed-length string buffer.
 *
 * Ensures that \c str[\c len] is '\\0', clamping \c len to \c capacity - 1
 * if necessary.
 *
 * @param str       The character buffer to null-terminate.
 * @param len       Current string length.
 * @param capacity  Total size of the character buffer in bytes.
 */
#ifdef _WIN32
void string_null_terminate(char *str, int len, int capacity);
#endif
/**@}*/
/* End of string utility functions */

/**
 * Write buffer contents to file.
 *
 * @param filename  The filename to write the buffer to.
 * @param buf       The buffer to write to the file.
 *
 * @return true on success, false otherwise.
 */
bool buffer_write_file(const char *filename, const struct buffer *buf);

/**
 * Append a string to the physical end of a buffer that was truncated by
 * \c buf_printf().
 *
 * If the buffer's forward capacity is one byte or less (i.e. it is full),
 * \c str is written at the very end of the allocated memory to act as a
 * truncation marker, provided it fits within the total buffer capacity.
 * This is used to append a "[more...]" suffix after hex-dump truncation.
 *
 * @param buf   The buffer to append the truncation marker to.
 * @param str   The null-terminated marker string to write.
 */
void buf_catrunc(struct buffer *buf, const char *str);

/**
 * Extract the next token from a buffer, delimited by a given character.
 *
 * Reads bytes from \c buf one at a time until \c delim or end-of-buffer is
 * encountered.  The token (without the delimiter) is written into \c line,
 * which is always null-terminated.  The delimiter byte is consumed from
 * \c buf but not included in \c line.
 *
 * @param buf    Source buffer to parse.  The consumed portion is advanced.
 * @param delim  Delimiter character.
 * @param line   Output buffer for the extracted token.
 * @param size   Size of \c line in bytes (must be > 0).
 *
 * @return false only when end-of-buffer is reached and no characters were
 *         extracted; true otherwise (including when a delimiter was found
 *         or \c line was truncated).
 */
bool buf_parse(struct buffer *buf, const int delim, char *line, const int size);

/** @name Hex Dump
 *  @brief Output a binary buffer to a hex string and return it.
 */
/**@{*/

/** Mask for the space_break_flags field of \c format_hex_ex(): number of
 *  bytes between separators (lower 8 bits). */
#define FHE_SPACE_BREAK_MASK 0xFF
/** Flag for \c format_hex_ex(): output hex digits in upper case. */
#define FHE_CAPS             0x100
/**
 * Format a binary buffer as a hex string.
 *
 * @param data              Pointer to the binary data to format.
 * @param size              Number of bytes to format.
 * @param maxoutput         Maximum number of output characters (0 = unlimited).
 *                          If the output is truncated, a "[more...]" suffix is
 *                          appended via \c buf_catrunc().
 * @param space_break_flags Lower 8 bits (\c FHE_SPACE_BREAK_MASK) give the
 *                          number of bytes between \c separator insertions.
 *                          Use \c FHE_CAPS to output upper-case hex digits.
 * @param separator         String to insert between groups of bytes.
 * @param gc                Garbage collection arena for the returned string.
 *
 * @return Null-terminated hex string allocated from \c gc.
 */
char *format_hex_ex(const uint8_t *data, size_t size, size_t maxoutput, unsigned int space_break_flags,
                    const char *separator, struct gc_arena *gc);

/**
 * Format a binary buffer as a hex string with spaces every 4 bytes.
 *
 * Convenience wrapper around \c format_hex_ex().
 *
 * @param data       Pointer to the binary data to format.
 * @param size       Number of bytes to format.
 * @param maxoutput  Maximum number of output characters (0 = unlimited).
 * @param gc         Garbage collection arena for the returned string.
 *
 * @return Null-terminated hex string allocated from \c gc.
 */
static inline char *
format_hex(const uint8_t *data, size_t size, size_t maxoutput, struct gc_arena *gc)
{
    return format_hex_ex(data, size, maxoutput, 4, " ", gc);
}
/**@}*/
/* End of Hex Dump */

/**
 * Return a sub-buffer of another buffer.
 *
 * Either allocates \c size bytes from the front or back of \c buf,
 * shrinking \c buf accordingly, and returns a buffer pointing into the
 * same memory.
 *
 * @param buf      Source buffer to carve the sub-buffer from.
 * @param size     Number of bytes to include in the sub-buffer.
 * @param prepend  If true, take bytes from the front of \c buf (prepend
 *                 space); if false, take bytes from the end (append space).
 *
 * @return A buffer referencing the allocated region, or an undefined buffer
 *         if \c buf has insufficient capacity.
 */
struct buffer buf_sub(struct buffer *buf, int size, bool prepend);

/**
 * Check whether \c len bytes can be appended to a buffer.
 *
 * @param buf   The buffer to check.
 * @param len   Number of bytes to append.
 *
 * @return true if \c buf is valid, \c len is within the allowed range, and
 *         there is sufficient capacity after the current content.
 */
static inline bool
buf_safe(const struct buffer *buf, size_t len)
{
    return buf_valid(buf) && buf_size_valid(len)
           && buf->offset + buf->len + (int)len <= buf->capacity;
}

/**
 * Check whether \c len bytes can be added to or removed from a buffer.
 *
 * Accepts negative \c len to verify that bytes can be removed (length
 * decreased).
 *
 * @param buf   The buffer to check.
 * @param len   Number of bytes to add (positive) or remove (negative).
 *
 * @return true if the resulting length would remain non-negative and within
 *         the allocated capacity.
 */
static inline bool
buf_safe_bidir(const struct buffer *buf, int len)
{
    if (buf_valid(buf) && buf_size_valid_signed(len))
    {
        int newlen = buf->len + len;
        return newlen >= 0 && buf->offset + newlen <= buf->capacity;
    }
    else
    {
        return false;
    }
}

/**
 * Return the number of bytes that can still be appended to the buffer.
 *
 * This is the space between the end of the current content and the end of
 * the allocated memory.
 *
 * @param buf   The buffer to query.
 *
 * @return Number of bytes available for appending, or 0 if \c buf is
 *         invalid.
 */
static inline int
buf_forward_capacity(const struct buffer *buf)
{
    if (buf_valid(buf))
    {
        int ret = buf->capacity - (buf->offset + buf->len);
        if (ret < 0)
        {
            ret = 0;
        }
        return ret;
    }
    else
    {
        return 0;
    }
}

/**
 * Return the total number of bytes available from the current offset to the
 * end of the allocated memory.
 *
 * Unlike \c buf_forward_capacity(), this includes the bytes already occupied
 * by the current content.
 *
 * @param buf   The buffer to query.
 *
 * @return Capacity minus offset, or 0 if \c buf is invalid.
 */
static inline int
buf_forward_capacity_total(const struct buffer *buf)
{
    if (buf_valid(buf))
    {
        int ret = buf->capacity - buf->offset;
        if (ret < 0)
        {
            ret = 0;
        }
        return ret;
    }
    else
    {
        return 0;
    }
}

/**
 * Return the number of bytes available for prepending to the buffer.
 *
 * This is the number of bytes between the start of the allocated memory and
 * the current content start (i.e. \c buf->offset).
 *
 * @param buf   The buffer to query.
 *
 * @return \c buf->offset, or 0 if \c buf is invalid.
 */
static inline int
buf_reverse_capacity(const struct buffer *buf)
{
    if (buf_valid(buf))
    {
        return buf->offset;
    }
    else
    {
        return 0;
    }
}

/**
 * Increase or decrease the length of a buffer.
 *
 * Adjusts \c buf->len by \c inc bytes.  A negative \c inc shrinks the
 * buffer.  The operation is bounds-checked via \c buf_safe_bidir().
 *
 * @param buf   The buffer to modify.
 * @param inc   Number of bytes to add to the length (may be negative).
 *
 * @return true on success, false if the adjustment would violate bounds.
 */
static inline bool
buf_inc_len(struct buffer *buf, int inc)
{
    if (!buf_safe_bidir(buf, inc))
    {
        return false;
    }
    buf->len += inc;
    return true;
}

/**
 * Make space at the front of a buffer for prepending data.
 *
 * Moves the content start backwards by \c size bytes, increasing \c len
 * and decreasing \c offset by the same amount.
 *
 * @param buf   The buffer to modify.
 * @param size  Number of bytes to reserve for prepending.
 *
 * @return Pointer to the newly reserved space (new content start), or NULL
 *         if \c buf is invalid or there is insufficient prepend capacity.
 */
static inline uint8_t *
buf_prepend(struct buffer *buf, ssize_t size)
{
    if (!buf_valid(buf) || size < 0 || size > buf->offset)
    {
        return NULL;
    }
    buf->offset -= (int)size;
    buf->len += (int)size;
    return BPTR(buf);
}

/**
 * Advance the content start of a buffer, consuming bytes from the front.
 *
 * Increases \c offset and decreases \c len by \c size bytes.
 *
 * @param buf   The buffer to advance.
 * @param size  Number of bytes to skip.
 *
 * @return true on success, false if \c buf is invalid or \c size exceeds
 *         the current length.
 */
static inline bool
buf_advance(struct buffer *buf, ssize_t size)
{
    if (!buf_valid(buf) || size < 0 || buf->len < size)
    {
        return false;
    }
    buf->offset += (int)size;
    buf->len -= (int)size;
    return true;
}

/**
 * Reserve space at the end of a buffer for writing.
 *
 * Increases \c buf->len by \c size and returns a pointer to the start of
 * the newly reserved region.
 *
 * @param buf   The buffer to allocate space in.
 * @param size  Number of bytes to reserve.
 *
 * @return Pointer to the start of the reserved space, or NULL if there is
 *         insufficient capacity.
 */
static inline uint8_t *
buf_write_alloc(struct buffer *buf, size_t size)
{
    uint8_t *ret;
    if (!buf_safe(buf, size))
    {
        return NULL;
    }
    ret = BPTR(buf) + buf->len;
    buf->len += (int)size;
    return ret;
}

/**
 * Consume bytes from the front of a buffer for reading.
 *
 * Returns a pointer to the current content start and advances the buffer
 * by \c size bytes.
 *
 * @param buf   The buffer to read from.
 * @param size  Number of bytes to consume.
 *
 * @return Pointer to the start of the consumed region, or NULL if \c size
 *         is negative or exceeds the current length.
 */
static inline uint8_t *
buf_read_alloc(struct buffer *buf, int size)
{
    uint8_t *ret;
    if (size < 0 || buf->len < size)
    {
        return NULL;
    }
    ret = BPTR(buf);
    buf->offset += size;
    buf->len -= size;
    return ret;
}

/**
 * Append data to a buffer.
 *
 * Copies \c size bytes from \c src to the end of \c dest.
 *
 * @param dest  Destination buffer.
 * @param src   Data to append.
 * @param size  Number of bytes to append.
 *
 * @return true on success, false if there is insufficient capacity.
 */
static inline bool
buf_write(struct buffer *dest, const void *src, size_t size)
{
    uint8_t *cp = buf_write_alloc(dest, size);
    if (!cp)
    {
        return false;
    }
    memcpy(cp, src, size);
    return true;
}

/**
 * Prepend data to a buffer.
 *
 * Copies \c size bytes from \c src into the prepend space at the front of
 * \c dest.
 *
 * @param dest  Destination buffer.
 * @param src   Data to prepend.
 * @param size  Number of bytes to prepend.
 *
 * @return true on success, false if there is insufficient prepend capacity.
 */
static inline bool
buf_write_prepend(struct buffer *dest, const void *src, int size)
{
    uint8_t *cp = buf_prepend(dest, size);
    if (!cp)
    {
        return false;
    }
    memcpy(cp, src, size);
    return true;
}

/**
 * Append a uint8_t to a buffer.
 *
 * @param dest  Destination buffer.
 * @param data  Byte to append.
 *
 * @return true on success, false if there is insufficient capacity.
 */
static inline bool
buf_write_u8(struct buffer *dest, uint8_t data)
{
    return buf_write(dest, &data, sizeof(uint8_t));
}

/**
 * Append a uint16_t to a buffer in network byte order.
 *
 * @param dest  Destination buffer.
 * @param data  Value to append (converted with \c htons()).
 *
 * @return true on success, false if there is insufficient capacity.
 */
static inline bool
buf_write_u16(struct buffer *dest, uint16_t data)
{
    uint16_t u16 = htons(data);
    return buf_write(dest, &u16, sizeof(uint16_t));
}

/**
 * Append a uint32_t to a buffer in network byte order.
 *
 * @param dest  Destination buffer.
 * @param data  Value to append (converted with \c htonl()).
 *
 * @return true on success, false if there is insufficient capacity.
 */
static inline bool
buf_write_u32(struct buffer *dest, uint32_t data)
{
    uint32_t u32 = htonl(data);
    return buf_write(dest, &u32, sizeof(uint32_t));
}

/**
 * Append a uint64_t to a buffer in network byte order.
 *
 * @param dest  Destination buffer.
 * @param data  Value to append (converted with \c htonll()).
 *
 * @return true on success, false if there is insufficient capacity.
 */
static inline bool
buf_write_u64(struct buffer *dest, uint64_t data)
{
    uint64_t u64 = htonll(data);
    return buf_write(dest, &u64, sizeof(uint64_t));
}

/**
 * Copy the content of one buffer to the end of another.
 *
 * @param dest  Destination buffer.
 * @param src   Source buffer.
 *
 * @return true on success, false if \c dest has insufficient capacity.
 */
static inline bool
buf_copy(struct buffer *dest, const struct buffer *src)
{
    return buf_write(dest, BPTR(src), BLENZ(src));
}

/**
 * Read \c n bytes from \c src and append them to \c dest.
 *
 * Consumes the bytes from \c src.
 *
 * @param dest  Destination buffer.
 * @param src   Source buffer (modified).
 * @param n     Number of bytes to copy.
 *
 * @return true on success, false if \c src has fewer than \c n bytes or
 *         \c dest has insufficient capacity.
 */
static inline bool
buf_copy_n(struct buffer *dest, struct buffer *src, int n)
{
    uint8_t *cp = buf_read_alloc(src, n);
    if (!cp)
    {
        return false;
    }
    return buf_write(dest, cp, n);
}

/**
 * Copy a range of bytes from one buffer into a specific position in another.
 *
 * Copies \c src_len bytes starting at \c src_index within \c src content
 * into \c dest at \c dest_index relative to the content start.  Updates
 * \c dest->len if the write extends beyond the current content.  Does not
 * advance either buffer's offset.
 *
 * @param dest        Destination buffer.
 * @param dest_index  Byte offset within \c dest content to write at.
 * @param src         Source buffer.
 * @param src_index   Byte offset within \c src content to read from.
 * @param src_len     Number of bytes to copy.
 *
 * @return true on success, false if any index or length is out of range.
 */
static inline bool
buf_copy_range(struct buffer *dest, int dest_index, const struct buffer *src, int src_index,
               int src_len)
{
    if (src_index < 0 || src_len < 0 || src_index + src_len > src->len || dest_index < 0
        || dest->offset + dest_index + src_len > dest->capacity)
    {
        return false;
    }
    memcpy(dest->data + dest->offset + dest_index, src->data + src->offset + src_index, src_len);
    if (dest_index + src_len > dest->len)
    {
        dest->len = dest_index + src_len;
    }
    return true;
}

/**
 * Truncate \c src to \c len bytes and copy any excess to \c dest.
 *
 * If \c src->len > \c len, \c src is truncated to \c len bytes and the
 * remaining bytes are appended to \c dest.  If \c src->len <= \c len,
 * nothing is copied and true is returned.
 *
 * @param dest  Destination buffer for the excess data.
 * @param src   Source buffer to truncate.
 * @param len   Maximum number of bytes to keep in \c src.
 *
 * @return true on success, false if \c len is negative or copying fails.
 */
static inline bool
buf_copy_excess(struct buffer *dest, struct buffer *src, int len)
{
    if (len < 0)
    {
        return false;
    }
    if (src->len > len)
    {
        struct buffer b = *src;
        src->len = len;
        if (!buf_advance(&b, len))
        {
            return false;
        }
        return buf_copy(dest, &b);
    }
    else
    {
        return true;
    }
}

/**
 * Read bytes from the front of a buffer into a caller-supplied destination.
 *
 * Consumes \c size bytes from \c src and copies them to \c dest.
 *
 * @param src   Source buffer (modified).
 * @param dest  Destination memory.
 * @param size  Number of bytes to read.
 *
 * @return true on success, false if \c src has fewer than \c size bytes.
 */
static inline bool
buf_read(struct buffer *src, void *dest, int size)
{
    uint8_t *cp = buf_read_alloc(src, size);
    if (!cp)
    {
        return false;
    }
    memcpy(dest, cp, size);
    return true;
}

/**
 * Return the first byte of the buffer without consuming it.
 *
 * @param buf   The buffer to peek at.
 *
 * @return The first byte as an unsigned value (0–255), or -1 if the buffer
 *         is empty.
 */
static inline int
buf_peek_u8(struct buffer *buf)
{
    int ret;
    if (BLEN(buf) < 1)
    {
        return -1;
    }
    ret = *BPTR(buf);
    return ret;
}

/**
 * Read and consume a uint8_t from the front of a buffer.
 *
 * @param buf   The buffer to read from.
 *
 * @return The byte value (0–255), or -1 if the buffer is empty.
 */
static inline int
buf_read_u8(struct buffer *buf)
{
    int ret = buf_peek_u8(buf);
    if (ret >= 0)
    {
        buf_advance(buf, 1);
    }
    return ret;
}

/**
 * Read and consume a uint16_t from the front of a buffer.
 *
 * The value is converted from network byte order via \c ntohs().
 *
 * @param buf   The buffer to read from.
 *
 * @return The host-byte-order value, or -1 if the buffer has fewer than 2
 *         bytes.
 */
static inline int
buf_read_u16(struct buffer *buf)
{
    uint16_t ret;
    if (!buf_read(buf, &ret, sizeof(uint16_t)))
    {
        return -1;
    }
    return ntohs(ret);
}

/**
 * Read and consume a uint32_t from the front of a buffer.
 *
 * The value is converted from network byte order via \c ntohl().
 *
 * @param buf   The buffer to read from.
 * @param good  If non-NULL, set to true on success or false on failure.
 *
 * @return The host-byte-order value, or 0 if the buffer has fewer than 4
 *         bytes (check \c *good to distinguish from a legitimate zero).
 */
static inline uint32_t
buf_read_u32(struct buffer *buf, bool *good)
{
    uint32_t ret;
    if (!buf_read(buf, &ret, sizeof(uint32_t)))
    {
        if (good)
        {
            *good = false;
        }
        return 0;
    }
    else
    {
        if (good)
        {
            *good = true;
        }
        return ntohl(ret);
    }
}

/**
 * Read and consume a uint64_t from the front of a buffer.
 *
 * The value is converted from network byte order via \c ntohll().
 *
 * @param buf   The buffer to read from.
 * @param good  If non-NULL, set to true on success or false on failure.
 *
 * @return The host-byte-order value, or 0 if the buffer has fewer than 8
 *         bytes (check \c *good to distinguish from a legitimate zero).
 */
static inline uint64_t
buf_read_u64(struct buffer *buf, bool *good)
{
    uint64_t ret;
    if (!buf_read(buf, &ret, sizeof(uint64_t)))
    {
        if (good)
        {
            *good = false;
        }
        return 0;
    }
    else
    {
        if (good)
        {
            *good = true;
        }
        return ntohll(ret);
    }
}

/** Return true if buffer contents are equal */
static inline bool
buf_equal(const struct buffer *a, const struct buffer *b)
{
    return BLEN(a) == BLEN(b) && 0 == memcmp(BPTR(a), BPTR(b), BLENZ(a));
}

/**
 * Compare src buffer contents with match.
 * *NOT* constant time. Do not use when comparing HMACs.
 */
static inline bool
buf_string_match(const struct buffer *src, const void *match, int size)
{
    if (size != src->len)
    {
        return false;
    }
    return memcmp(BPTR(src), match, size) == 0;
}

/**
 * Compare first size bytes of src buffer contents with match.
 * *NOT* constant time. Do not use when comparing HMACs.
 */
static inline bool
buf_string_match_head(const struct buffer *src, const void *match, int size)
{
    if (size < 0 || size > src->len)
    {
        return false;
    }
    return memcmp(BPTR(src), match, size) == 0;
}

/**
 * Return true if the head of \c src matches the string \c match.
 *
 * Compares the first \c strlen(match) bytes of \c src content with \c match.
 * *NOT* constant time. Do not use when comparing HMACs.
 *
 * @param src    Buffer whose head is compared.
 * @param match  Null-terminated string to compare against.
 *
 * @return true if the buffer starts with \c match.
 */
bool buf_string_match_head_str(const struct buffer *src, const char *match);

/**
 * Compare the head of \c src with \c match and advance past it if equal.
 *
 * If the buffer starts with \c match, the matched bytes are consumed from
 * \c src.  *NOT* constant time. Do not use when comparing HMACs.
 *
 * @param src    Buffer to compare and advance.
 * @param match  Null-terminated string to compare against.
 *
 * @return true if the buffer started with \c match (and was advanced).
 */
bool buf_string_compare_advance(struct buffer *src, const char *match);

/**
 * Return the number of bytes in a buffer up to and including a delimiter.
 *
 * The count includes the delimiter byte, so it can be passed straight to
 * \c buf_copy_excess() to split off a complete record, keeping the
 * delimiter with it.
 *
 * @param buf    The buffer to scan.
 * @param delim  Delimiter byte to search for.
 *
 * @return Byte count including the first \c delim, or -1 if the buffer
 *         contains no \c delim.
 */
int buf_substring_len(const struct buffer *buf, int delim);

/**
 * Return a printable representation of a string that might be NULL.
 *
 * @param str   String to print, or NULL.
 *
 * @return \c str if non-NULL, otherwise the string \c "[NULL]".
 */
const char *np(const char *str);

/** @name Character classes
 *  @brief Check or modify strings based on classes of allowed
 *         or forbidden characters.
 */
/**@{*/
#define CC_ANY  (1 << 0)           /**< any character */
#define CC_NULL (1 << 1)           /**< null character \0 */

#define CC_ALNUM  (1 << 2)         /**< alphanumeric \c isalnum() */
#define CC_ALPHA  (1 << 3)         /**< alphabetic \c isalpha() */
#define CC_ASCII  (1 << 4)         /**< ASCII character */
#define CC_CNTRL  (1 << 5)         /**< control character \c iscntrl() */
#define CC_DIGIT  (1 << 6)         /**< digit \c isdigit() */
#define CC_PRINT  (1 << 7)         /**< printable (>= 32, != 127) */
#define CC_PUNCT  (1 << 8)         /**< punctuation \c ispunct() */
#define CC_SPACE  (1 << 9)         /**< whitespace \c isspace() */
#define CC_XDIGIT (1 << 10)        /**< hex digit \c isxdigit() */

#define CC_BLANK   (1 << 11)       /**< space or tab */
#define CC_NEWLINE (1 << 12)       /**< newline */
#define CC_CR      (1 << 13)       /**< carriage return */

#define CC_BACKSLASH     (1 << 14) /**< backslash */
#define CC_UNDERBAR      (1 << 15) /**< underscore */
#define CC_DASH          (1 << 16) /**< dash */
#define CC_DOT           (1 << 17) /**< dot */
#define CC_COMMA         (1 << 18) /**< comma */
#define CC_COLON         (1 << 19) /**< colon */
#define CC_SLASH         (1 << 20) /**< slash */
#define CC_SINGLE_QUOTE  (1 << 21) /**< single quote */
#define CC_DOUBLE_QUOTE  (1 << 22) /**< double quote */
#define CC_REVERSE_QUOTE (1 << 23) /**< reverse quote */
#define CC_AT            (1 << 24) /**< at sign */
#define CC_EQUAL         (1 << 25) /**< equal sign */
#define CC_LESS_THAN     (1 << 26) /**< less than sign */
#define CC_GREATER_THAN  (1 << 27) /**< greater than sign */
#define CC_PIPE          (1 << 28) /**< pipe */
#define CC_QUESTION_MARK (1 << 29) /**< question mark */
#define CC_ASTERISK      (1 << 30) /**< asterisk */

/* macro classes */
#define CC_NAME (CC_ALNUM | CC_UNDERBAR) /**< alphanumeric plus underscore */
#define CC_CRLF (CC_CR | CC_NEWLINE)     /**< carriage return or newline */

/**
 * Test whether a character belongs to one or more character classes.
 *
 * @param c      The character to test.
 * @param flags  Bitmask of \c CC_* character class flags.
 *
 * @return true if \c c matches any of the classes specified in \c flags.
 */
bool char_class(const unsigned char c, const unsigned int flags);

/**
 * Test whether all characters in a string satisfy a character class filter.
 *
 * @param str        The null-terminated string to test.
 * @param inclusive  Classes that are permitted (characters must match at
 *                   least one of these).
 * @param exclusive  Classes that are forbidden (characters must not match
 *                   any of these, even if they also match \c inclusive).
 *
 * @return true if every character in \c str is permitted.
 */
bool string_class(const char *str, const unsigned int inclusive, const unsigned int exclusive);

/**
 * Modifies a string in place by replacing certain classes of characters of it with a specified
 * character.
 *
 * Guaranteed to not increase the length of the string.
 * If replace is 0, characters are skipped instead of replaced.
 *
 * @param str The string to be modified.
 * @param inclusive The character classes not to be replaced.
 * @param exclusive Character classes to be replaced even if they are also in inclusive.
 * @param replace The character to replace the specified character classes with.
 * @return True if the string was not modified, false otherwise.
 */
bool string_mod(char *str, const unsigned int inclusive, const unsigned int exclusive,
                const char replace);


/**
 * Check a buffer if it only consists of allowed characters.
 *
 * @param buf The buffer to be checked.
 * @param inclusive The character classes that are allowed.
 * @param exclusive Character classes that are not allowed even if they are also in inclusive.
 * @return True if the string consists only of allowed characters, false otherwise.
 */
bool string_check_buf(struct buffer *buf, const unsigned int inclusive,
                      const unsigned int exclusive);

/**
 * Returns a copy of a string with certain classes of characters of it replaced with a specified
 * character.
 *
 * If replace is 0, characters are skipped instead of replaced.
 *
 * @param str       The input string to be modified.
 * @param inclusive Character classes not to be replaced.
 * @param exclusive Character classes to be replaced even if they are also in inclusive.
 * @param replace   The character to replace the specified character classes with.
 * @param gc        The garbage collector arena to allocate memory from.
 *
 * @return The modified string with characters replaced within the specified range.
 */
const char *string_mod_const(const char *str, const unsigned int inclusive,
                             const unsigned int exclusive, const char replace, struct gc_arena *gc);
/**@}*/

/**
 * Replace all leading occurrences of a character in a string.
 *
 * Scans from the start of \c str and replaces every consecutive \c match
 * character with \c replace, stopping at the first character that does not
 * match.
 *
 * @param str      The null-terminated string to modify in place.
 * @param match    The character to replace.
 * @param replace  The replacement character.
 */
void string_replace_leading(char *str, const char match, const char replace);

/**
 * Return true iff \c str starts with \c prefix.
 *
 * @param str     The string to test.
 * @param prefix  The prefix to look for.
 */
static inline bool
strprefix(const char *str, const char *prefix)
{
    return 0 == strncmp(str, prefix, strlen(prefix));
}

/**
 * Like snprintf() but returns an boolean.
 *
 * To check the return value of snprintf() one needs to
 * do multiple comparisons of the \p size parameter
 * against the return value. Doesn't get prettier by
 * them being different types with different signedness
 * and size.
 *
 * So this function allows to wrap all of that into one
 * boolean return value.
 *
 * @return true if snprintf() was successful and not truncated.
 */
bool checked_snprintf(char *str, size_t size, const char *format, ...)
#ifdef __GNUC__
#if __USE_MINGW_ANSI_STDIO
    __attribute__((format(gnu_printf, 3, 4)))
#else
    __attribute__((format(__printf__, 3, 4)))
#endif
#endif
    ;

/*
 * Verify that a pointer is correctly aligned
 */
#ifdef VERIFY_ALIGNMENT
/**
 * Assert that the content pointer of \c buf is 4-byte aligned.
 *
 * Only compiled in when \c VERIFY_ALIGNMENT is defined.  Called via the
 * \c verify_align_4() macro.
 *
 * @param buf   Buffer whose content pointer is to be checked.
 * @param file  Source file of the call site (for the error message).
 * @param line  Source line of the call site (for the error message).
 */
void valign4(const struct buffer *buf, const char *file, const int line);

#define verify_align_4(ptr) valign4(buf, __FILE__, __LINE__)
#else
#define verify_align_4(ptr)
#endif

/** @name Garbage Collection
 *  @brief Basic garbage collection, mostly for routines that return
 *         char ptrs to malloced strings.
 */
/**@{*/

/**
 * Move all allocations from one garbage collection arena to another.
 *
 * After the call \c src is empty and all entries previously in \c src are
 * owned by \c dest.
 *
 * @param dest  Arena to move allocations into.
 * @param src   Arena to move allocations from (emptied on return).
 */
void gc_transfer(struct gc_arena *dest, struct gc_arena *src);

/**
 * Free all plain allocations in a garbage collection arena.
 *
 * Internal implementation called by \c gc_free().  Do not call directly.
 *
 * @param a  The arena whose \c list entries are to be freed.
 */
void x_gc_free(struct gc_arena *a);

/**
 * Free all specially-allocated entries in a garbage collection arena.
 *
 * Internal implementation called by \c gc_free().  Do not call directly.
 * Invokes the custom free function stored in each \c gc_entry_special.
 *
 * @param a  The arena whose \c list_special entries are to be freed.
 */
void x_gc_freespecial(struct gc_arena *a);

/**
 * Return true iff the arena contains at least one allocation.
 *
 * @param a  The arena to test.
 */
static inline bool
gc_defined(struct gc_arena *a)
{
    return a->list != NULL;
}

/**
 * Initialise a garbage collection arena to an empty state.
 *
 * @param a  The arena to initialise.
 */
static inline void
gc_init(struct gc_arena *a)
{
    a->list = NULL;
    a->list_special = NULL;
}

/**
 * Detach all allocations from an arena without freeing them.
 *
 * After this call the arena is empty.  The caller takes responsibility for
 * freeing the previously registered allocations.
 *
 * @param a  The arena to detach.
 */
static inline void
gc_detach(struct gc_arena *a)
{
    gc_init(a);
}

/**
 * Allocate and return a new, empty garbage collection arena.
 *
 * @return An initialised \c gc_arena with empty lists.
 */
static inline struct gc_arena
gc_new(void)
{
    struct gc_arena ret;
    gc_init(&ret);
    return ret;
}

/**
 * Free all allocations in a garbage collection arena.
 *
 * Calls \c x_gc_free() and \c x_gc_freespecial() as needed to release all
 * registered memory.
 *
 * @param a  The arena to free.
 */
static inline void
gc_free(struct gc_arena *a)
{
    if (a->list)
    {
        x_gc_free(a);
    }
    if (a->list_special)
    {
        x_gc_freespecial(a);
    }
}

/**
 * Free all allocations in a garbage collection arena and reinitialise it.
 *
 * Equivalent to calling \c gc_free() followed by \c gc_init().
 *
 * @param a  The arena to reset.
 */
static inline void
gc_reset(struct gc_arena *a)
{
    gc_free(a);
}

/*
 * Allocate memory to hold a structure
 */

/* When allocating arrays make sure we do not use a excessive amount
 * of memory.
 */
#if UINTPTR_MAX <= UINT32_MAX
/* 1 GB on 32bit systems, they usually can only allocate 2 GB for the
 * whole process.
 */
/** Maximum size for a single array allocation (checked by \c array_mult_safe()). */
#define ALLOC_SIZE_MAX (1u << 30)
#else
/** Maximum size for a single array allocation (checked by \c array_mult_safe()). */
#define ALLOC_SIZE_MAX ((size_t)1 << 32) /* 4 GB */
#endif

/**
 * Allocate memory for a single object of the given type.
 *
 * Calls \c check_malloc_return() to abort on allocation failure.
 *
 * @param dptr  Pointer variable that receives the allocation.
 * @param type  Type of the object to allocate.
 */
#define ALLOC_OBJ(dptr, type)                                       \
    {                                                               \
        check_malloc_return((dptr) = (type *)malloc(sizeof(type))); \
    }

/**
 * Allocate and zero-initialise memory for a single object of the given type.
 *
 * @param dptr  Pointer variable that receives the allocation.
 * @param type  Type of the object to allocate.
 */
#define ALLOC_OBJ_CLEAR(dptr, type)      \
    {                                    \
        ALLOC_OBJ(dptr, type);           \
        memset((dptr), 0, sizeof(type)); \
    }

/**
 * Allocate memory for an array of \c n elements of the given type.
 *
 * Uses \c array_mult_safe() to guard against size overflow.
 * Calls \c check_malloc_return() to abort on allocation failure.
 *
 * @param dptr  Pointer variable that receives the allocation.
 * @param type  Element type of the array.
 * @param n     Number of elements.
 */
#define ALLOC_ARRAY(dptr, type, n)                                                           \
    {                                                                                        \
        check_malloc_return((dptr) = (type *)malloc(array_mult_safe(sizeof(type), (n), 0))); \
    }

/**
 * Allocate a garbage-collected array of \c n elements of the given type.
 *
 * @param dptr  Pointer variable that receives the allocation.
 * @param type  Element type of the array.
 * @param n     Number of elements.
 * @param gc    Garbage collection arena to register the allocation with.
 */
#define ALLOC_ARRAY_GC(dptr, type, n, gc)                                               \
    {                                                                                   \
        (dptr) = (type *)gc_malloc(array_mult_safe(sizeof(type), (n), 0), false, (gc)); \
    }

/**
 * Allocate and zero-initialise an array of \c n elements of the given type.
 *
 * @param dptr  Pointer variable that receives the allocation.
 * @param type  Element type of the array.
 * @param n     Number of elements.
 */
#define ALLOC_ARRAY_CLEAR(dptr, type, n)                            \
    {                                                               \
        ALLOC_ARRAY(dptr, type, n);                                 \
        memset((dptr), 0, (array_mult_safe(sizeof(type), (n), 0))); \
    }

/**
 * Allocate and zero-initialise a garbage-collected array of \c n elements.
 *
 * @param dptr  Pointer variable that receives the allocation.
 * @param type  Element type of the array.
 * @param n     Number of elements.
 * @param gc    Garbage collection arena to register the allocation with.
 */
#define ALLOC_ARRAY_CLEAR_GC(dptr, type, n, gc)                                        \
    {                                                                                  \
        (dptr) = (type *)gc_malloc(array_mult_safe(sizeof(type), (n), 0), true, (gc)); \
    }

/**
 * Allocate and zero-initialise a garbage-collected variable-length structure.
 *
 * Allocates \c sizeof(type) + \c n * \c sizeof(atype) bytes for a structure
 * that embeds a variable-length array of \c atype as its last member.
 *
 * @param dptr   Pointer variable that receives the allocation.
 * @param type   Type of the enclosing structure.
 * @param atype  Element type of the variable-length array member.
 * @param n      Number of array elements.
 * @param gc     Garbage collection arena to register the allocation with.
 */
#define ALLOC_VAR_ARRAY_CLEAR_GC(dptr, type, atype, n, gc)                                         \
    {                                                                                              \
        (dptr) = (type *)gc_malloc(array_mult_safe(sizeof(atype), (n), sizeof(type)), true, (gc)); \
    }

/**
 * Allocate a garbage-collected object of the given type (uninitialised).
 *
 * @param dptr  Pointer variable that receives the allocation.
 * @param type  Type of the object to allocate.
 * @param gc    Garbage collection arena to register the allocation with.
 */
#define ALLOC_OBJ_GC(dptr, type, gc)                           \
    {                                                          \
        (dptr) = (type *)gc_malloc(sizeof(type), false, (gc)); \
    }

/**
 * Allocate and zero-initialise a garbage-collected object of the given type.
 *
 * @param dptr  Pointer variable that receives the allocation.
 * @param type  Type of the object to allocate.
 * @param gc    Garbage collection arena to register the allocation with.
 */
#define ALLOC_OBJ_CLEAR_GC(dptr, type, gc)                    \
    {                                                         \
        (dptr) = (type *)gc_malloc(sizeof(type), true, (gc)); \
    }

/**
 * Abort if a memory allocation returned NULL.
 *
 * @param p  Return value from \c malloc() or similar; calls \c out_of_memory()
 *           if \c p is NULL.
 */
static inline void
check_malloc_return(void *p)
{
    if (!p)
    {
        out_of_memory();
    }
}
/**@}*/
/* End of GC */

/** @name Buffer Lists
 *  @brief Manage lists of buffers
 */
/**@{*/

/** One node in a \c buffer_list linked list. */
struct buffer_entry
{
    struct buffer buf;         /**< The buffer stored in this list node. */
    struct buffer_entry *next; /**< Pointer to the next node, or NULL. */
};

/** A singly-linked list of buffers, with head/tail pointers for O(1) push. */
struct buffer_list
{
    struct buffer_entry *head; /**< Next item to pop/peek. */
    struct buffer_entry *tail; /**< Last item pushed. */
    size_t size;               /**< Current number of entries. */
    size_t max_size;           /**< Maximum number of entries allowed. */
};

/**
 * Allocate an empty buffer list of capacity \c max_size.
 *
 * @return the new list
 */
struct buffer_list *buffer_list_new(void);

/**
 * Frees a buffer list and all the buffers in it.
 *
 * @param ol    the list to free
 */
void buffer_list_free(struct buffer_list *ol);

/**
 * Checks if the list is valid and non-empty
 *
 * @param ol    the list to check
 *
 * @return true iff \c ol is not NULL and contains at least one buffer
 */
bool buffer_list_defined(const struct buffer_list *ol);

/**
 * Empty the list \c ol and frees all the contained buffers
 *
 * @param ol    the list to reset
 */
void buffer_list_reset(struct buffer_list *ol);

/**
 * Allocates and appends a new buffer containing \c str as data to \c ol
 *
 * @param ol    the list to append the new buffer to
 * @param str   the string to copy into the new buffer
 */
void buffer_list_push(struct buffer_list *ol, const char *str);

/**
 * Allocates and appends a new buffer containing \c data of length \c size.
 *
 * @param ol    the list to append the new buffer to
 * @param data  the data to copy into the new buffer
 * @param size  the length of \c data to copy into the buffer
 *
 * @return the new buffer
 */
struct buffer_entry *buffer_list_push_data(struct buffer_list *ol, const void *data, size_t size);

/**
 * Retrieve the head buffer
 *
 * @param ol    the list to retrieve the buffer from
 *
 * @return a pointer to the head buffer or NULL if the list is empty
 */
struct buffer *buffer_list_peek(struct buffer_list *ol);

/**
 * Advance past \c n bytes in the head buffer, popping it if it becomes empty.
 *
 * \c n must not exceed the length of the head buffer; passing a larger value
 * triggers an assertion failure.
 *
 * @param ol  The list whose head buffer is to be advanced.
 * @param n   Number of bytes to skip in the head buffer.
 */
void buffer_list_advance(struct buffer_list *ol, ssize_t n);

/**
 * Remove and free the head buffer of the list.
 *
 * Does nothing if \c ol is NULL or empty.
 *
 * @param ol  The list to pop from.
 */
void buffer_list_pop(struct buffer_list *ol);

/**
 * Aggregates as many buffers as possible from \c bl in a new buffer of maximum
 * length \c max_len .
 * All the aggregated buffers are removed from the list and replaced by the new
 * one, followed by any additional (non-aggregated) data.
 *
 * @param bl    the list of buffer to aggregate
 * @param max   the maximum length of the aggregated buffer
 */
void buffer_list_aggregate(struct buffer_list *bl, const size_t max);

/**
 * Aggregates as many buffers as possible from \c bl in a new buffer
 * of maximum length \c max_len . \c sep is written after
 * each copied buffer (also after the last one). All the aggregated buffers are
 * removed from the list and replaced by the new one, followed by any additional
 * (non-aggregated) data.
 * Nothing happens if \c max_len is not enough to aggregate at least 2 buffers.
 *
 * @param bl        the list of buffer to aggregate
 * @param max_len   the maximum length of the aggregated buffer
 * @param sep       the separator to put between buffers during aggregation
 */
void buffer_list_aggregate_separator(struct buffer_list *bl, const size_t max_len, const char *sep);

/**
 * Read a file into a buffer list, one buffer per line.
 *
 * Opens \c fn for reading and pushes each line into a newly allocated buffer
 * list using \c fgets().  Lines longer than \c max_line_len - 1 bytes are
 * split across multiple consecutive buffers.
 *
 * @param fn            Path to the file to read.
 * @param max_line_len  Maximum number of bytes (including null terminator)
 *                      read per \c fgets() call.
 *
 * @return Pointer to the new buffer list, or NULL if the file could not be
 *         opened or memory allocation failed.
 */
struct buffer_list *buffer_list_file(const char *fn, int max_line_len);

/**
 * buffer_read_from_file - copy the content of a file into a buffer
 *
 * @param filename  path to the file to read
 * @param gc        the garbage collector to use when allocating the buffer. It
 *                  is passed to alloc_buf_gc() and therefore can be NULL.
 *
 * @return the buffer storing the file content or an invalid buffer in case of
 * error
 */
struct buffer buffer_read_from_file(const char *filename, struct gc_arena *gc);
/**@}*/
/* End of Buffer Lists */

#endif /* BUFFER_H */
