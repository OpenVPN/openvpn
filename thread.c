/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2008 OpenVPN Technologies, Inc. <sales@openvpn.net>
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

#include "syshead.h"

#ifdef USE_PTHREAD

#include "thread.h"
#include "buffer.h"
#include "common.h"
#include "error.h"
#include "crypto.h"

#include "memdbg.h"

static struct sparse_mutex *ssl_mutex;  /* GLOBAL */

static void
ssl_pthreads_locking_callback (int mode, int type, char *file, int line)
{
  dmsg (D_OPENSSL_LOCK, "SSL LOCK thread=%4lu mode=%s lock=%s %s:%d",
	   CRYPTO_thread_id (),
	   (mode & CRYPTO_LOCK) ? "l" : "u",
	   (type & CRYPTO_READ) ? "r" : "w", file, line);

  if (mode & CRYPTO_LOCK)
    pthread_mutex_lock (&ssl_mutex[type].mutex);
  else
    pthread_mutex_unlock (&ssl_mutex[type].mutex);
}

static unsigned long
ssl_pthreads_thread_id (void)
{
  unsigned long ret;

  ret = (unsigned long) pthread_self ();
  return ret;
}

static void
ssl_thread_setup (void)
{
  int i;

#error L_MSG needs to be initialized as a recursive mutex

  ssl_mutex = OPENSSL_malloc (CRYPTO_num_locks () * sizeof (struct sparse_mutex));
  for (i = 0; i < CRYPTO_num_locks (); i++)
    pthread_mutex_init (&ssl_mutex[i].mutex, NULL);

  CRYPTO_set_id_callback ((unsigned long (*)(void)) ssl_pthreads_thread_id);
  CRYPTO_set_locking_callback ((void (*)(int, int, const char*, int)) ssl_pthreads_locking_callback);
}

static void
ssl_thread_cleanup (void)
{
  int i;

  dmsg (D_OPENSSL_LOCK, "SSL LOCK cleanup");
  CRYPTO_set_locking_callback (NULL);
  for (i = 0; i < CRYPTO_num_locks (); i++)
    pthread_mutex_destroy (&ssl_mutex[i].mutex);
  OPENSSL_free (ssl_mutex);
}

struct sparse_mutex mutex_array[N_MUTEXES]; /* GLOBAL */
bool pthread_initialized;                   /* GLOBAL */

openvpn_thread_t
openvpn_thread_create (void *(*start_routine) (void *), void* arg)
{
  openvpn_thread_t ret;
  ASSERT (pthread_initialized);
  ASSERT (!pthread_create (&ret, NULL, start_routine, arg));
  dmsg (D_THREAD_DEBUG, "CREATE THREAD ID=%lu", (unsigned long)ret);
  return ret;
}

void
openvpn_thread_join (openvpn_thread_t id)
{
  ASSERT (pthread_initialized);
  pthread_join (id, NULL);
}

void
openvpn_thread_init ()
{
  int i;

  ASSERT (!pthread_initialized);

  msg (M_INFO, "PTHREAD support initialized");

  /* initialize OpenSSL library locking */
#if defined(USE_CRYPTO) && defined(USE_SSL)
  ssl_thread_setup();
#endif
  
  /* initialize static mutexes */
  for (i = 0; i < N_MUTEXES; i++)
    ASSERT (!pthread_mutex_init (&mutex_array[i].mutex, NULL));

  msg_thread_init ();

  pthread_initialized = true;
}

void
openvpn_thread_cleanup ()
{
  if (pthread_initialized)
    {
      int i;

      pthread_initialized = false;

      /* cleanup OpenSSL library locking */
#if defined(USE_CRYPTO) && defined(USE_SSL)
      ssl_thread_cleanup();
#endif

      /* destroy static mutexes */
      for (i = 0; i < N_MUTEXES; i++)
	ASSERT (!pthread_mutex_destroy (&mutex_array[i].mutex));

      msg_thread_uninit ();
    }
}

#else
static void dummy(void) {}
#endif
