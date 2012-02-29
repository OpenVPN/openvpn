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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if P2MP_SERVER

#include "list.h"
#include "misc.h"

#include "memdbg.h"

struct hash *
hash_init (const int n_buckets,
	   const uint32_t iv,
	   uint32_t (*hash_function)(const void *key, uint32_t iv),
	   bool (*compare_function)(const void *key1, const void *key2))
{
  struct hash *h;
  int i;

  ASSERT (n_buckets > 0);
  ALLOC_OBJ_CLEAR (h, struct hash);
  h->n_buckets = (int) adjust_power_of_2 (n_buckets);
  h->mask = h->n_buckets - 1;
  h->hash_function = hash_function;
  h->compare_function = compare_function;
  h->iv = iv;
  ALLOC_ARRAY (h->buckets, struct hash_bucket, h->n_buckets);
  for (i = 0; i < h->n_buckets; ++i)
    {
      struct hash_bucket *b = &h->buckets[i];
      b->list = NULL;
    }
  return h;
}

void
hash_free (struct hash *hash)
{
  int i;
  for (i = 0; i < hash->n_buckets; ++i)
    {
      struct hash_bucket *b = &hash->buckets[i];
      struct hash_element *he = b->list;

      while (he)
	{
	  struct hash_element *next = he->next;
	  free (he);
	  he = next;
	}
    }
  free (hash->buckets);
  free (hash);
}

struct hash_element *
hash_lookup_fast (struct hash *hash,
		  struct hash_bucket *bucket,
		  const void *key,
		  uint32_t hv)
{
  struct hash_element *he;
  struct hash_element *prev = NULL;

  he = bucket->list;

  while (he)
    {
      if (hv == he->hash_value && (*hash->compare_function)(key, he->key))
	{
	  /* move to head of list */
	  if (prev)
	    {
	      prev->next = he->next;
	      he->next = bucket->list;
	      bucket->list = he;
	    }
	  return he;
	}
      prev = he;
      he = he->next;
    }

  return NULL;
}

bool
hash_remove_fast (struct hash *hash,
		  struct hash_bucket *bucket,
		  const void *key,
		  uint32_t hv)
{
  struct hash_element *he;
  struct hash_element *prev = NULL;

  he = bucket->list;

  while (he)
    {
      if (hv == he->hash_value && (*hash->compare_function)(key, he->key))
	{
	  if (prev)
	    prev->next = he->next;
	  else
	    bucket->list = he->next;
	  free (he);
	  --hash->n_elements;
	  return true;
	}
      prev = he;
      he = he->next;
    }
  return false;
}

bool
hash_add (struct hash *hash, const void *key, void *value, bool replace)
{
  uint32_t hv;
  struct hash_bucket *bucket;
  struct hash_element *he;
  bool ret = false;

  hv = hash_value (hash, key);
  bucket = &hash->buckets[hv & hash->mask];

  if ((he = hash_lookup_fast (hash, bucket, key, hv))) /* already exists? */
    {
      if (replace)
	{
	  he->value = value;
	  ret = true;
	}
    }
  else
    {
      hash_add_fast (hash, bucket, key, hv, value);
      ret = true;
    }

  return ret;
}

void
hash_remove_by_value (struct hash *hash, void *value)
{
  struct hash_iterator hi;
  struct hash_element *he;

  hash_iterator_init (hash, &hi);
  while ((he = hash_iterator_next (&hi)))
    {
      if (he->value == value)
	hash_iterator_delete_element (&hi);
    }
  hash_iterator_free (&hi);
}

static void
hash_remove_marked (struct hash *hash, struct hash_bucket *bucket)
{
  struct hash_element *prev = NULL;
  struct hash_element *he = bucket->list;

  while (he)
    {
      if (!he->key) /* marked? */
	{
	  struct hash_element *newhe;
	  if (prev)
	    newhe = prev->next = he->next;
	  else
	    newhe = bucket->list = he->next;
	  free (he);
	  --hash->n_elements;
	  he = newhe;
	}
      else
	{
	  prev = he;
	  he = he->next;
	}
    }
}

uint32_t
void_ptr_hash_function (const void *key, uint32_t iv)
{
  return hash_func ((const void *)&key, sizeof (key), iv);
}

bool
void_ptr_compare_function (const void *key1, const void *key2)
{
  return key1 == key2;
}

void
hash_iterator_init_range (struct hash *hash,
		       struct hash_iterator *hi,
		       int start_bucket,
		       int end_bucket)
{
  if (end_bucket > hash->n_buckets)
    end_bucket = hash->n_buckets;

  ASSERT (start_bucket >= 0 && start_bucket <= end_bucket);

  hi->hash = hash;
  hi->elem = NULL;
  hi->bucket = NULL;
  hi->last = NULL;
  hi->bucket_marked = false;
  hi->bucket_index_start = start_bucket;
  hi->bucket_index_end = end_bucket;
  hi->bucket_index = hi->bucket_index_start - 1;
}

void
hash_iterator_init (struct hash *hash,
		    struct hash_iterator *hi)
{
  hash_iterator_init_range (hash, hi, 0, hash->n_buckets);
}

static inline void
hash_iterator_lock (struct hash_iterator *hi, struct hash_bucket *b)
{
  hi->bucket = b;
  hi->last = NULL;
  hi->bucket_marked = false;
}

static inline void
hash_iterator_unlock (struct hash_iterator *hi)
{
  if (hi->bucket)
    {
      if (hi->bucket_marked)
	{
	  hash_remove_marked (hi->hash, hi->bucket);
	  hi->bucket_marked = false;
	}
      hi->bucket = NULL;
      hi->last = NULL;
    }
}

static inline void
hash_iterator_advance (struct hash_iterator *hi)
{
  hi->last = hi->elem;
  hi->elem = hi->elem->next;
}

void
hash_iterator_free (struct hash_iterator *hi)
{
  hash_iterator_unlock (hi);
}

struct hash_element *
hash_iterator_next (struct hash_iterator *hi)
{
  struct hash_element *ret = NULL;
  if (hi->elem)
    {
      ret = hi->elem;
      hash_iterator_advance (hi);
    }
  else
    {
      while (++hi->bucket_index < hi->bucket_index_end)
	{
	  struct hash_bucket *b;
	  hash_iterator_unlock (hi);
	  b = &hi->hash->buckets[hi->bucket_index];
	  if (b->list)
	    {
	      hash_iterator_lock (hi, b);
	      hi->elem = b->list;
	      if (hi->elem)
		{
		  ret = hi->elem;
		  hash_iterator_advance (hi);
		  break;
		}
	    }
	}
    }
  return ret;
}

void
hash_iterator_delete_element (struct hash_iterator *hi)
{
  ASSERT (hi->last);
  hi->last->key = NULL;
  hi->bucket_marked = true;
}


#ifdef LIST_TEST

/*
 * Test the hash code by implementing a simple
 * word frequency algorithm.
 */

struct word
{
  const char *word;
  int n;
};

static uint32_t
word_hash_function (const void *key, uint32_t iv)
{
  const char *str = (const char *) key;
  const int len = strlen (str);
  return hash_func ((const uint8_t *)str, len, iv);
}

static bool
word_compare_function (const void *key1, const void *key2)
{
  return strcmp ((const char *)key1, (const char *)key2) == 0;
}

static void
print_nhash (struct hash *hash)
{
  struct hash_iterator hi;
  struct hash_element *he;
  int count = 0;

  hash_iterator_init (hash, &hi, true);

  while ((he = hash_iterator_next (&hi)))
    {
      printf ("%d ", (int) he->value);
      ++count;
    }
  printf ("\n");

  hash_iterator_free (&hi);
  ASSERT (count == hash_n_elements (hash));
}

static void
rmhash (struct hash *hash, const char *word)
{
  hash_remove (hash, word);
}

void
list_test (void)
{
  openvpn_thread_init ();

  {
    struct gc_arena gc = gc_new ();
    struct hash *hash = hash_init (10000, get_random (), word_hash_function, word_compare_function);
    struct hash *nhash = hash_init (256, get_random (), word_hash_function, word_compare_function);

    printf ("hash_init n_buckets=%d mask=0x%08x\n", hash->n_buckets, hash->mask);
  
    /* parse words from stdin */
    while (true)
      {
	char buf[256];
	char wordbuf[256];
	int wbi;
	int bi;
	char c;

	if (!fgets(buf, sizeof(buf), stdin))
	  break;

	bi = wbi = 0;
	do
	  {
	    c = buf[bi++];
	    if (isalnum (c) || c == '_')
	      {
		ASSERT (wbi < (int) sizeof (wordbuf));
		wordbuf[wbi++] = c;
	      }
	    else
	      {
		if (wbi)
		  {
		    struct word *w;
		    ASSERT (wbi < (int) sizeof (wordbuf));
		    wordbuf[wbi++] = '\0';
		  
		    /* word is parsed from stdin */

		    /* does it already exist in table? */
		    w = (struct word *) hash_lookup (hash, wordbuf);

		    if (w)
		      {
			/* yes, increment count */
			++w->n;
		      }
		    else
		      {
			/* no, make a new object */
			ALLOC_OBJ_GC (w, struct word, &gc);
			w->word = string_alloc (wordbuf, &gc);
			w->n = 1;
			ASSERT (hash_add (hash, w->word, w, false));
			ASSERT (hash_add (nhash, w->word, (void*) ((random() & 0x0F) + 1), false));
		      }
		  }
		wbi = 0;
	      }
	  } while (c);
      }

#if 1
    /* remove some words from the table */
    {
      rmhash (hash, "true");
      rmhash (hash, "false");
    }
#endif

    /* output contents of hash table */
    {
      int base;
      int inc = 0;
      int count = 0;

      for (base = 0; base < hash_n_buckets (hash); base += inc) {
	struct hash_iterator hi;
	struct hash_element *he;
	inc = (get_random () % 3) + 1;
	hash_iterator_init_range (hash, &hi, true, base, base + inc);

	while ((he = hash_iterator_next (&hi)))
	  {
	    struct word *w = (struct word *) he->value;
	    printf ("%6d '%s'\n", w->n, w->word);
	    ++count;
	  }

	hash_iterator_free (&hi);
      }
      ASSERT (count == hash_n_elements (hash));
    }
	
#if 1
    /* test hash_remove_by_value function */
    {
      int i;
      for (i = 1; i <= 16; ++i)
	{
	  printf ("[%d] ***********************************\n", i);
	  print_nhash (nhash);
	  hash_remove_by_value (nhash, (void *) i, true);
	}
      printf ("FINAL **************************\n");
      print_nhash (nhash);
    }
#endif

    hash_free (hash);
    hash_free (nhash);
    gc_free (&gc);
  }

  openvpn_thread_cleanup ();
}

#endif

/*
--------------------------------------------------------------------
hash() -- hash a variable-length key into a 32-bit value
  k     : the key (the unaligned variable-length array of bytes)
  len   : the length of the key, counting by bytes
  level : can be any 4-byte value
Returns a 32-bit value.  Every bit of the key affects every bit of
the return value.  Every 1-bit and 2-bit delta achieves avalanche.
About 36+6len instructions.

The best hash table sizes are powers of 2.  There is no need to do
mod a prime (mod is sooo slow!).  If you need less than 32 bits,
use a bitmask.  For example, if you need only 10 bits, do
  h = (h & hashmask(10));
In which case, the hash table should have hashsize(10) elements.

If you are hashing n strings (uint8_t **)k, do it like this:
  for (i=0, h=0; i<n; ++i) h = hash( k[i], len[i], h);

By Bob Jenkins, 1996.  bob_jenkins@burtleburtle.net.  You may use this
code any way you wish, private, educational, or commercial.  It's free.

See http://burlteburtle.net/bob/hash/evahash.html
Use for hash table lookup, or anything where one collision in 2^32 is
acceptable.  Do NOT use for cryptographic purposes.

--------------------------------------------------------------------

mix -- mix 3 32-bit values reversibly.
For every delta with one or two bit set, and the deltas of all three
  high bits or all three low bits, whether the original value of a,b,c
  is almost all zero or is uniformly distributed,
* If mix() is run forward or backward, at least 32 bits in a,b,c
  have at least 1/4 probability of changing.
* If mix() is run forward, every bit of c will change between 1/3 and
  2/3 of the time.  (Well, 22/100 and 78/100 for some 2-bit deltas.)
mix() was built out of 36 single-cycle latency instructions in a 
  structure that could supported 2x parallelism, like so:
      a -= b; 
      a -= c; x = (c>>13);
      b -= c; a ^= x;
      b -= a; x = (a<<8);
      c -= a; b ^= x;
      c -= b; x = (b>>13);
      ...
  Unfortunately, superscalar Pentiums and Sparcs can't take advantage 
  of that parallelism.  They've also turned some of those single-cycle
  latency instructions into multi-cycle latency instructions.  Still,
  this is the fastest good hash I could find.  There were about 2^^68
  to choose from.  I only looked at a billion or so.

James Yonan Notes:

* This function is faster than it looks, and appears to be
  appropriate for our usage in OpenVPN which is primarily
  for hash-table based address lookup (IPv4, IPv6, and Ethernet MAC).
  NOTE: This function is never used for cryptographic purposes, only
  to produce evenly-distributed indexes into hash tables.

* Benchmark results: 11.39 machine cycles per byte on a P2 266Mhz,
                     and 12.1 machine cycles per byte on a
                     2.2 Ghz P4 when hashing a 6 byte string.
--------------------------------------------------------------------
*/

#define mix(a,b,c)               \
{                                \
  a -= b; a -= c; a ^= (c>>13);  \
  b -= c; b -= a; b ^= (a<<8);   \
  c -= a; c -= b; c ^= (b>>13);  \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16);  \
  c -= a; c -= b; c ^= (b>>5);   \
  a -= b; a -= c; a ^= (c>>3);   \
  b -= c; b -= a; b ^= (a<<10);  \
  c -= a; c -= b; c ^= (b>>15);  \
}

uint32_t
hash_func (const uint8_t *k, uint32_t length, uint32_t initval)
{
  uint32_t a, b, c, len;

  /* Set up the internal state */
  len = length;
  a = b = 0x9e3779b9;	     /* the golden ratio; an arbitrary value */
  c = initval;		     /* the previous hash value */

   /*---------------------------------------- handle most of the key */
  while (len >= 12)
    {
      a += (k[0] + ((uint32_t) k[1] << 8)
	         + ((uint32_t) k[2] << 16)
	         + ((uint32_t) k[3] << 24));
      b += (k[4] + ((uint32_t) k[5] << 8)
	         + ((uint32_t) k[6] << 16)
	         + ((uint32_t) k[7] << 24));
      c += (k[8] + ((uint32_t) k[9] << 8)
	         + ((uint32_t) k[10] << 16)
	         + ((uint32_t) k[11] << 24));
      mix (a, b, c);
      k += 12;
      len -= 12;
    }

   /*------------------------------------- handle the last 11 bytes */
  c += length;
  switch (len)		    /* all the case statements fall through */
    {
    case 11:
      c += ((uint32_t) k[10] << 24);
    case 10:
      c += ((uint32_t) k[9] << 16);
    case 9:
      c += ((uint32_t) k[8] << 8);
      /* the first byte of c is reserved for the length */
    case 8:
      b += ((uint32_t) k[7] << 24);
    case 7:
      b += ((uint32_t) k[6] << 16);
    case 6:
      b += ((uint32_t) k[5] << 8);
    case 5:
      b += k[4];
    case 4:
      a += ((uint32_t) k[3] << 24);
    case 3:
      a += ((uint32_t) k[2] << 16);
    case 2:
      a += ((uint32_t) k[1] << 8);
    case 1:
      a += k[0];
      /* case 0: nothing left to add */
    }
  mix (a, b, c);
   /*-------------------------------------- report the result */
  return c;
}

#else
static void dummy(void) {}
#endif /* P2MP_SERVER */
