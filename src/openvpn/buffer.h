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

#ifndef BUFFER_H
#define BUFFER_H

#include "basic.h"
#include "error.h"

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
@code
uint8_t *content_start    = buffer.data + buffer.offset;
uint8_t *content_end      = buffer.data + buffer.offset + buffer.len;
int      prepend_capacity = buffer.offset;
int      append_capacity  = buffer.capacity - (buffer.offset + buffer.len);
@endcode
 */
struct buffer
{
  int capacity;                 /**< Size in bytes of memory allocated by
                                 *   \c malloc(). */
  int offset;                   /**< Offset in bytes of the actual content
                                 *   within the allocated memory. */
  int len;                      /**< Length in bytes of the actual content
                                 *   within the allocated memory. */
  uint8_t *data;                /**< Pointer to the allocated memory. */

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
  struct gc_entry *next;        /**< Pointer to the next item in the
                                 *   linked list. */
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
  struct gc_entry *list;        /**< First element of the linked list of
                                 *   \c gc_entry structures. */
};


#define BPTR(buf)  (buf_bptr(buf))
#define BEND(buf)  (buf_bend(buf))
#define BLAST(buf) (buf_blast(buf))
#define BLEN(buf)  (buf_len(buf))
#define BDEF(buf)  (buf_defined(buf))
#define BSTR(buf)  (buf_str(buf))
#define BCAP(buf)  (buf_forward_capacity (buf))

void buf_clear (struct buffer *buf);

struct buffer clear_buf (void);
void free_buf (struct buffer *buf);

bool buf_assign (struct buffer *dest, const struct buffer *src);

void string_clear (char *str);
int string_array_len (const char **array);

size_t array_mult_safe (const size_t m1, const size_t m2, const size_t extra);

#define PA_BRACKET (1<<0)
char *print_argv (const char **p, struct gc_arena *gc, const unsigned int flags);

void buf_size_error (const size_t size);

/* for dmalloc debugging */

#ifdef DMALLOC

#define alloc_buf(size)               alloc_buf_debug (size, __FILE__, __LINE__)
#define alloc_buf_gc(size, gc)        alloc_buf_gc_debug (size, gc, __FILE__, __LINE__);
#define clone_buf(buf)                clone_buf_debug (buf, __FILE__, __LINE__);
#define gc_malloc(size, clear, arena) gc_malloc_debug (size, clear, arena, __FILE__, __LINE__)
#define string_alloc(str, gc)         string_alloc_debug (str, gc, __FILE__, __LINE__)
#define string_alloc_buf(str, gc)     string_alloc_buf_debug (str, gc, __FILE__, __LINE__)

struct buffer alloc_buf_debug (size_t size, const char *file, int line);
struct buffer alloc_buf_gc_debug (size_t size, struct gc_arena *gc, const char *file, int line);
struct buffer clone_buf_debug (const struct buffer* buf, const char *file, int line);
void *gc_malloc_debug (size_t size, bool clear, struct gc_arena *a, const char *file, int line);
char *string_alloc_debug (const char *str, struct gc_arena *gc, const char *file, int line);
struct buffer string_alloc_buf_debug (const char *str, struct gc_arena *gc, const char *file, int line);

#else

struct buffer alloc_buf (size_t size);
struct buffer alloc_buf_gc (size_t size, struct gc_arena *gc); /* allocate buffer with garbage collection */
struct buffer clone_buf (const struct buffer* buf);
void *gc_malloc (size_t size, bool clear, struct gc_arena *a);
char *string_alloc (const char *str, struct gc_arena *gc);
struct buffer string_alloc_buf (const char *str, struct gc_arena *gc);

#endif

#ifdef BUF_INIT_TRACKING
#define buf_init(buf, offset) buf_init_debug (buf, offset, __FILE__, __LINE__)
bool buf_init_debug (struct buffer *buf, int offset, const char *file, int line);
#else
#define buf_init(buf, offset) buf_init_dowork (buf, offset)
#endif


/* inline functions */

static inline bool
buf_defined (const struct buffer *buf)
{
  return buf->data != NULL;
}

static inline bool
buf_valid (const struct buffer *buf)
{
  return likely (buf->data != NULL) && likely (buf->len >= 0);
}

static inline uint8_t *
buf_bptr (const struct buffer *buf)
{
  if (buf_valid (buf))
    return buf->data + buf->offset;
  else
    return NULL;
}

static int
buf_len (const struct buffer *buf)
{
  if (buf_valid (buf))
    return buf->len;
  else
    return 0;
}

static inline uint8_t *
buf_bend (const struct buffer *buf)
{
  return buf_bptr (buf) + buf_len (buf);
}

static inline uint8_t *
buf_blast (const struct buffer *buf)
{
  if (buf_len (buf) > 0)
    return buf_bptr (buf) + buf_len (buf) - 1;
  else
    return NULL;
}

static inline bool
buf_size_valid (const size_t size)
{
  return likely (size < BUF_SIZE_MAX);
}

static inline bool
buf_size_valid_signed (const int size)
{
  return likely (size >= -BUF_SIZE_MAX) && likely (size < BUF_SIZE_MAX);
}

static inline char *
buf_str (const struct buffer *buf)
{
  return (char *)buf_bptr(buf);
}

static inline void
buf_reset (struct buffer *buf)
{
  buf->capacity = 0;
  buf->offset = 0;
  buf->len = 0;
  buf->data = NULL;
}

static inline void
buf_reset_len (struct buffer *buf)
{
  buf->len = 0;
  buf->offset = 0;
}

static inline bool
buf_init_dowork (struct buffer *buf, int offset)
{
  if (offset < 0 || offset > buf->capacity || buf->data == NULL)
    return false;
  buf->len = 0;
  buf->offset = offset;
  return true;
}

static inline void
buf_set_write (struct buffer *buf, uint8_t *data, int size)
{
  if (!buf_size_valid (size))
    buf_size_error (size);
  buf->len = 0;
  buf->offset = 0;
  buf->capacity = size;
  buf->data = data;
  if (size > 0 && data)
    *data = 0;
}

static inline void
buf_set_read (struct buffer *buf, const uint8_t *data, int size)
{
  if (!buf_size_valid (size))
    buf_size_error (size);
  buf->len = buf->capacity = size;
  buf->offset = 0;
  buf->data = (uint8_t *)data;
}

/* Like strncpy but makes sure dest is always null terminated */
static inline void
strncpynt (char *dest, const char *src, size_t maxlen)
{
  strncpy (dest, src, maxlen);
  if (maxlen > 0)
    dest[maxlen - 1] = 0;
}

/* return true if string contains at least one numerical digit */
static inline bool
has_digit (const unsigned char* src)
{
  unsigned char c;
  while ((c = *src++))
    {
      if (isdigit(c))
	return true;
    }
  return false;
}

/*
 * printf append to a buffer with overflow check
 */
bool buf_printf (struct buffer *buf, const char *format, ...)
#ifdef __GNUC__
#if __USE_MINGW_ANSI_STDIO
	__attribute__ ((format (gnu_printf, 2, 3)))
#else
	__attribute__ ((format (__printf__, 2, 3)))
#endif
#endif
    ;

/*
 * puts append to a buffer with overflow check
 */
bool buf_puts (struct buffer *buf, const char *str);

/*
 * Like snprintf but guarantees null termination for size > 0
 */
bool openvpn_snprintf(char *str, size_t size, const char *format, ...)
#ifdef __GNUC__
#if __USE_MINGW_ANSI_STDIO
	__attribute__ ((format (gnu_printf, 3, 4)))
#else
	__attribute__ ((format (__printf__, 3, 4)))
#endif
#endif
    ;

/*
 * remove/add trailing characters
 */

void buf_null_terminate (struct buffer *buf);
void buf_chomp (struct buffer *buf);
void buf_rmtail (struct buffer *buf, uint8_t remove);

/*
 * non-buffer string functions
 */
void chomp (char *str);
void rm_trailing_chars (char *str, const char *what_to_delete);
const char *skip_leading_whitespace (const char *str);
void string_null_terminate (char *str, int len, int capacity);

/*
 * Write string in buf to file descriptor fd.
 * NOTE: requires that string be null terminated.
 */
void buf_write_string_file (const struct buffer *buf, const char *filename, int fd);

/*
 * write a string to the end of a buffer that was
 * truncated by buf_printf
 */
void buf_catrunc (struct buffer *buf, const char *str);

/*
 * convert a multi-line output to one line
 */
void convert_to_one_line (struct buffer *buf);

/*
 * Parse a string based on a given delimiter char
 */
bool buf_parse (struct buffer *buf, const int delim, char *line, const int size);

/*
 * Hex dump -- Output a binary buffer to a hex string and return it.
 */
char *
format_hex_ex (const uint8_t *data, int size, int maxoutput,
	       int space_break, const char* separator,
	       struct gc_arena *gc);

static inline char *
format_hex (const uint8_t *data, int size, int maxoutput, struct gc_arena *gc)
{
  return format_hex_ex (data, size, maxoutput, 4, " ", gc);
}

/*
 * Return a buffer that is a subset of another buffer.
 */
struct buffer buf_sub (struct buffer *buf, int size, bool prepend);

/*
 * Check if sufficient space to append to buffer.
 */

static inline bool
buf_safe (const struct buffer *buf, int len)
{
  return buf_valid (buf) && buf_size_valid (len)
    && buf->offset + buf->len + len <= buf->capacity;
}

static inline bool
buf_safe_bidir (const struct buffer *buf, int len)
{
  if (buf_valid (buf) && buf_size_valid_signed (len))
    {
      const int newlen = buf->len + len;
      return newlen >= 0 && buf->offset + newlen <= buf->capacity;
    }
  else
    return false;
}

static inline int
buf_forward_capacity (const struct buffer *buf)
{
  if (buf_valid (buf))
    {
      int ret = buf->capacity - (buf->offset + buf->len);
      if (ret < 0)
	ret = 0;
      return ret;
    }
  else
    return 0;
}

static inline int
buf_forward_capacity_total (const struct buffer *buf)
{
  if (buf_valid (buf))
    {
      int ret = buf->capacity - buf->offset;
      if (ret < 0)
	ret = 0;
      return ret;
    }
  else
    return 0;
}

static inline int
buf_reverse_capacity (const struct buffer *buf)
{
  if (buf_valid (buf))
    return buf->offset;
  else
    return 0;
}

static inline bool
buf_inc_len (struct buffer *buf, int inc)
{
  if (!buf_safe_bidir (buf, inc))
    return false;
  buf->len += inc;
  return true;
}

/*
 * Make space to prepend to a buffer.
 * Return NULL if no space.
 */

static inline uint8_t *
buf_prepend (struct buffer *buf, int size)
{
  if (!buf_valid (buf) || size < 0 || size > buf->offset)
    return NULL;
  buf->offset -= size;
  buf->len += size;
  return BPTR (buf);
}

static inline bool
buf_advance (struct buffer *buf, int size)
{
  if (!buf_valid (buf) || size < 0 || buf->len < size)
    return false;
  buf->offset += size;
  buf->len -= size;
  return true;
}

/*
 * Return a pointer to allocated space inside a buffer.
 * Return NULL if no space.
 */

static inline uint8_t *
buf_write_alloc (struct buffer *buf, int size)
{
  uint8_t *ret;
  if (!buf_safe (buf, size))
    return NULL;
  ret = BPTR (buf) + buf->len;
  buf->len += size;
  return ret;
}

static inline uint8_t *
buf_write_alloc_prepend (struct buffer *buf, int size, bool prepend)
{
  return prepend ? buf_prepend (buf, size) : buf_write_alloc (buf, size);
}

static inline uint8_t *
buf_read_alloc (struct buffer *buf, int size)
{
  uint8_t *ret;
  if (size < 0 || buf->len < size)
    return NULL;
  ret = BPTR (buf);
  buf->offset += size;
  buf->len -= size;
  return ret;
}

static inline bool
buf_write (struct buffer *dest, const void *src, int size)
{
  uint8_t *cp = buf_write_alloc (dest, size);
  if (!cp)
    return false;
  memcpy (cp, src, size);
  return true;
}

static inline bool
buf_write_prepend (struct buffer *dest, const void *src, int size)
{
  uint8_t *cp = buf_prepend (dest, size);
  if (!cp)
    return false;
  memcpy (cp, src, size);
  return true;
}

static inline bool
buf_write_u8 (struct buffer *dest, int data)
{
  uint8_t u8 = (uint8_t) data;
  return buf_write (dest, &u8, sizeof (uint8_t));
}

static inline bool
buf_write_u16 (struct buffer *dest, int data)
{
  uint16_t u16 = htons ((uint16_t) data);
  return buf_write (dest, &u16, sizeof (uint16_t));
}

static inline bool
buf_write_u32 (struct buffer *dest, int data)
{
  uint32_t u32 = htonl ((uint32_t) data);
  return buf_write (dest, &u32, sizeof (uint32_t));
}

static inline bool
buf_copy (struct buffer *dest, const struct buffer *src)
{
  return buf_write (dest, BPTR (src), BLEN (src));
}

static inline bool
buf_copy_n (struct buffer *dest, struct buffer *src, int n)
{
  uint8_t *cp = buf_read_alloc (src, n);
  if (!cp)
    return false;
  return buf_write (dest, cp, n);
}

static inline bool
buf_copy_range (struct buffer *dest,
		int dest_index,
		const struct buffer *src,
		int src_index,
		int src_len)
{
  if (src_index < 0
      || src_len < 0
      || src_index + src_len > src->len
      || dest_index < 0
      || dest->offset + dest_index + src_len > dest->capacity)
    return false;
  memcpy (dest->data + dest->offset + dest_index, src->data + src->offset + src_index, src_len);
  if (dest_index + src_len > dest->len)
    dest->len = dest_index + src_len;
  return true;
}

/* truncate src to len, copy excess data beyond len to dest */
static inline bool
buf_copy_excess (struct buffer *dest,
		 struct buffer *src,
		 int len)
{
  if (len < 0)
    return false;
  if (src->len > len)
    {
      struct buffer b = *src;
      src->len = len;
      if (!buf_advance (&b, len))
	return false;
      return buf_copy (dest, &b);
    }
  else
    {
      return true;
    }
}

static inline bool
buf_read (struct buffer *src, void *dest, int size)
{
  uint8_t *cp = buf_read_alloc (src, size);
  if (!cp)
    return false;
  memcpy (dest, cp, size);
  return true;
}

static inline int
buf_read_u8 (struct buffer *buf)
{
  int ret;
  if (BLEN (buf) < 1)
    return -1;
  ret = *BPTR(buf);
  buf_advance (buf, 1);
  return ret;
}

static inline int
buf_read_u16 (struct buffer *buf)
{
  uint16_t ret;
  if (!buf_read (buf, &ret, sizeof (uint16_t)))
    return -1;
  return ntohs (ret);
}

static inline uint32_t
buf_read_u32 (struct buffer *buf, bool *good)
{
  uint32_t ret;
  if (!buf_read (buf, &ret, sizeof (uint32_t)))
    {
      if (good)
	*good = false;
      return 0;
    }
  else
    {
      if (good)
	*good = true;
      return ntohl (ret);
    }
}

/**
 * Compare src buffer contents with match.
 * *NOT* constant time. Do not use when comparing HMACs.
 */
static inline bool
buf_string_match (const struct buffer *src, const void *match, int size)
{
  if (size != src->len)
    return false;
  return memcmp (BPTR (src), match, size) == 0;
}

/**
 * Compare first size bytes of src buffer contents with match.
 * *NOT* constant time. Do not use when comparing HMACs.
 */
static inline bool
buf_string_match_head (const struct buffer *src, const void *match, int size)
{
  if (size < 0 || size > src->len)
    return false;
  return memcmp (BPTR (src), match, size) == 0;
}

bool buf_string_match_head_str (const struct buffer *src, const char *match);
bool buf_string_compare_advance (struct buffer *src, const char *match);
int buf_substring_len (const struct buffer *buf, int delim);

/*
 * Print a string which might be NULL
 */
const char *np (const char *str);

/*#define CHARACTER_CLASS_DEBUG*/

/* character classes */

#define CC_ANY                (1<<0)
#define CC_NULL               (1<<1)

#define CC_ALNUM              (1<<2)
#define CC_ALPHA              (1<<3)
#define CC_ASCII              (1<<4)
#define CC_CNTRL              (1<<5)
#define CC_DIGIT              (1<<6)
#define CC_PRINT              (1<<7)
#define CC_PUNCT              (1<<8)
#define CC_SPACE              (1<<9)
#define CC_XDIGIT             (1<<10)

#define CC_BLANK              (1<<11)
#define CC_NEWLINE            (1<<12)
#define CC_CR                 (1<<13)

#define CC_BACKSLASH          (1<<14)
#define CC_UNDERBAR           (1<<15)
#define CC_DASH               (1<<16)
#define CC_DOT                (1<<17)
#define CC_COMMA              (1<<18)
#define CC_COLON              (1<<19)
#define CC_SLASH              (1<<20)
#define CC_SINGLE_QUOTE       (1<<21)
#define CC_DOUBLE_QUOTE       (1<<22)
#define CC_REVERSE_QUOTE      (1<<23)
#define CC_AT                 (1<<24)
#define CC_EQUAL              (1<<25)
#define CC_LESS_THAN          (1<<26)
#define CC_GREATER_THAN       (1<<27)
#define CC_PIPE               (1<<28)
#define CC_QUESTION_MARK      (1<<29)
#define CC_ASTERISK           (1<<30)

/* macro classes */
#define CC_NAME               (CC_ALNUM|CC_UNDERBAR)
#define CC_CRLF               (CC_CR|CC_NEWLINE)

bool char_class (const unsigned char c, const unsigned int flags);
bool string_class (const char *str, const unsigned int inclusive, const unsigned int exclusive);
bool string_mod (char *str, const unsigned int inclusive, const unsigned int exclusive, const char replace);

const char *string_mod_const (const char *str,
			      const unsigned int inclusive,
			      const unsigned int exclusive,
			      const char replace,
			      struct gc_arena *gc);

void string_replace_leading (char *str, const char match, const char replace);

#ifdef CHARACTER_CLASS_DEBUG
void character_class_debug (void);
#endif

/*
 * Verify that a pointer is correctly aligned
 */
#ifdef VERIFY_ALIGNMENT
  void valign4 (const struct buffer *buf, const char *file, const int line);
# define verify_align_4(ptr) valign4(buf, __FILE__, __LINE__)
#else
# define verify_align_4(ptr)
#endif

/*
 * Very basic garbage collection, mostly for routines that return
 * char ptrs to malloced strings.
 */

void gc_transfer (struct gc_arena *dest, struct gc_arena *src);

void x_gc_free (struct gc_arena *a);

static inline bool
gc_defined (struct gc_arena *a)
{
  return a->list != NULL;
}

static inline void
gc_init (struct gc_arena *a)
{
  a->list = NULL;
}

static inline void
gc_detach (struct gc_arena *a)
{
  gc_init (a);
}

static inline struct gc_arena
gc_new (void)
{
  struct gc_arena ret;
  ret.list = NULL;
  return ret;
}

static inline void
gc_free (struct gc_arena *a)
{
  if (a->list)
    x_gc_free (a);
}

static inline void
gc_reset (struct gc_arena *a)
{
  gc_free (a);
}

/*
 * Allocate memory to hold a structure
 */

#define ALLOC_OBJ(dptr, type) \
{ \
  check_malloc_return ((dptr) = (type *) malloc (sizeof (type))); \
}

#define ALLOC_OBJ_CLEAR(dptr, type) \
{ \
  ALLOC_OBJ (dptr, type); \
  memset ((dptr), 0, sizeof(type)); \
}

#define ALLOC_ARRAY(dptr, type, n) \
{ \
  check_malloc_return ((dptr) = (type *) malloc (array_mult_safe (sizeof (type), (n), 0))); \
}

#define ALLOC_ARRAY_GC(dptr, type, n, gc) \
{ \
  (dptr) = (type *) gc_malloc (array_mult_safe (sizeof (type), (n), 0), false, (gc)); \
}

#define ALLOC_ARRAY_CLEAR(dptr, type, n) \
{ \
  ALLOC_ARRAY (dptr, type, n); \
  memset ((dptr), 0, (array_mult_safe (sizeof(type), (n), 0)));	\
}

#define ALLOC_ARRAY_CLEAR_GC(dptr, type, n, gc) \
{ \
  (dptr) = (type *) gc_malloc (array_mult_safe (sizeof (type), (n), 0), true, (gc)); \
}

#define ALLOC_VAR_ARRAY_CLEAR_GC(dptr, type, atype, n, gc)	\
{ \
  (dptr) = (type *) gc_malloc (array_mult_safe (sizeof (atype), (n), sizeof (type)), true, (gc)); \
}

#define ALLOC_OBJ_GC(dptr, type, gc) \
{ \
  (dptr) = (type *) gc_malloc (sizeof (type), false, (gc)); \
}

#define ALLOC_OBJ_CLEAR_GC(dptr, type, gc) \
{ \
  (dptr) = (type *) gc_malloc (sizeof (type), true, (gc)); \
}

static inline void
check_malloc_return (void *p)
{
  if (!p)
    out_of_memory ();
}

/*
 * Manage lists of buffers
 */

#ifdef ENABLE_BUFFER_LIST

struct buffer_entry
{
  struct buffer buf;
  struct buffer_entry *next;
};

struct buffer_list
{
  struct buffer_entry *head; /* next item to pop/peek */
  struct buffer_entry *tail; /* last item pushed */
  int size;                  /* current number of entries */
  int max_size;              /* maximum size list should grow to */
};

struct buffer_list *buffer_list_new (const int max_size);
void buffer_list_free (struct buffer_list *ol);

bool buffer_list_defined (const struct buffer_list *ol);
void buffer_list_reset (struct buffer_list *ol);

void buffer_list_push (struct buffer_list *ol, const unsigned char *str);
struct buffer_entry *buffer_list_push_data (struct buffer_list *ol, const uint8_t *data, size_t size);
struct buffer *buffer_list_peek (struct buffer_list *ol);
void buffer_list_advance (struct buffer_list *ol, int n);
void buffer_list_pop (struct buffer_list *ol);

void buffer_list_aggregate (struct buffer_list *bl, const size_t max);

struct buffer_list *buffer_list_file (const char *fn, int max_line_len);

#endif

#endif /* BUFFER_H */
