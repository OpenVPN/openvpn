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

/*
 * Win32-specific OpenVPN code, targetted at the mingw
 * development environment.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#ifdef WIN32

#include "buffer.h"
#include "error.h"
#include "mtu.h"
#include "sig.h"
#include "win32.h"
#include "misc.h"

#include "memdbg.h"

/*
 * Windows internal socket API state (opaque).
 */
static struct WSAData wsa_state; /* GLOBAL */

/*
 * Should we call win32_pause() on program exit?
 */
static bool pause_exit_enabled = false; /* GLOBAL */

/*
 * win32_signal is used to get input from the keyboard
 * if we are running in a console, or get input from an
 * event object if we are running as a service.
 */

struct win32_signal win32_signal; /* GLOBAL */

/*
 * Save our old window title so we can restore
 * it on exit.
 */
struct window_title window_title; /* GLOBAL*/

/*
 * Special global semaphore used to protect network
 * shell commands from simultaneous instantiation.
 */

struct semaphore netcmd_semaphore; /* GLOBAL */

/*
 * Windows system pathname such as c:\windows
 */
static char *win_sys_path = NULL; /* GLOBAL */

void
init_win32 (void)
{
  if (WSAStartup(0x0101, &wsa_state))
    {
      msg (M_ERR, "WSAStartup failed");
    }
  window_title_clear (&window_title);
  win32_signal_clear (&win32_signal);
  netcmd_semaphore_init ();
}

void
uninit_win32 (void)
{
  netcmd_semaphore_close ();
  if (pause_exit_enabled)
    {
      if (win32_signal.mode == WSO_MODE_UNDEF)
	{
	  struct win32_signal w;
	  win32_signal_open (&w, WSO_FORCE_CONSOLE, NULL, false);
	  win32_pause (&w);
	  win32_signal_close (&w);
	}
      else
	win32_pause (&win32_signal);
    }
  window_title_restore (&window_title);
  win32_signal_close (&win32_signal);
  WSACleanup ();
  free (win_sys_path);
}

void
set_pause_exit_win32 (void)
{
  pause_exit_enabled = true;
}

bool
init_security_attributes_allow_all (struct security_attributes *obj)
{
  CLEAR (*obj);

  obj->sa.nLength = sizeof (SECURITY_ATTRIBUTES);
  obj->sa.lpSecurityDescriptor = &obj->sd;
  obj->sa.bInheritHandle = FALSE;
  if (!InitializeSecurityDescriptor (&obj->sd, SECURITY_DESCRIPTOR_REVISION))
    return false;
  if (!SetSecurityDescriptorDacl (&obj->sd, TRUE, NULL, FALSE))
    return false;
  return true;
}

void
overlapped_io_init (struct overlapped_io *o,
		    const struct frame *frame,
		    BOOL event_state,
		    bool tuntap_buffer) /* if true: tuntap buffer, if false: socket buffer */
{
  CLEAR (*o);

  /* manual reset event, initially set according to event_state */
  o->overlapped.hEvent = CreateEvent (NULL, TRUE, event_state, NULL);
  if (o->overlapped.hEvent == NULL)
    msg (M_ERR, "Error: overlapped_io_init: CreateEvent failed");

  /* allocate buffer for overlapped I/O */
  alloc_buf_sock_tun (&o->buf_init, frame, tuntap_buffer, 0);
}

void
overlapped_io_close (struct overlapped_io *o)
{
  if (o->overlapped.hEvent)
    {
      if (!CloseHandle (o->overlapped.hEvent))
	msg (M_WARN | M_ERRNO, "Warning: CloseHandle failed on overlapped I/O event object");
    }
  free_buf (&o->buf_init);
}

char *
overlapped_io_state_ascii (const struct overlapped_io *o)
{
  switch (o->iostate)
    {
    case IOSTATE_INITIAL:
      return "0";
    case IOSTATE_QUEUED:
      return "Q";
    case IOSTATE_IMMEDIATE_RETURN:
      return "1";
    }
  return "?";
}

/*
 * Event-based notification of network events
 */

void
init_net_event_win32 (struct rw_handle *event, long network_events, socket_descriptor_t sd, unsigned int flags)
{
  /* manual reset events, initially set to unsignaled */

  /* initialize write event */
  if (!(flags & NE32_PERSIST_EVENT) || !event->write)
    {
      if (flags & NE32_WRITE_EVENT)
	{
	  event->write = CreateEvent (NULL, TRUE, FALSE, NULL);
	  if (event->write == NULL)
	    msg (M_ERR, "Error: init_net_event_win32: CreateEvent (write) failed");
	}
      else
	event->write = NULL;
    }

  /* initialize read event */
  if (!(flags & NE32_PERSIST_EVENT) || !event->read)
    {
      event->read = CreateEvent (NULL, TRUE, FALSE, NULL);
      if (event->read == NULL)
	msg (M_ERR, "Error: init_net_event_win32: CreateEvent (read) failed");
    }
  
  /* setup network events to change read event state */
  if (WSAEventSelect (sd, event->read, network_events) != 0)
    msg (M_FATAL | M_ERRNO, "Error: init_net_event_win32: WSAEventSelect call failed");
}

long
reset_net_event_win32 (struct rw_handle *event, socket_descriptor_t sd)
{
  WSANETWORKEVENTS wne;  
  if (WSAEnumNetworkEvents (sd, event->read, &wne) != 0)
    {
      msg (M_FATAL | M_ERRNO, "Error: reset_net_event_win32: WSAEnumNetworkEvents call failed");
      return 0; /* NOTREACHED */
    }
  else
    return wne.lNetworkEvents;
}

void
close_net_event_win32 (struct rw_handle *event, socket_descriptor_t sd, unsigned int flags)
{
  if (event->read)
    {
      if (socket_defined (sd))
	{
	  if (WSAEventSelect (sd, event->read, 0) != 0)
	    msg (M_WARN | M_ERRNO, "Warning: close_net_event_win32: WSAEventSelect call failed");
	}
      if (!ResetEvent (event->read))
	msg (M_WARN | M_ERRNO, "Warning: ResetEvent (read) failed in close_net_event_win32");
      if (!(flags & NE32_PERSIST_EVENT))
	{
	  if (!CloseHandle (event->read))
	    msg (M_WARN | M_ERRNO, "Warning: CloseHandle (read) failed in close_net_event_win32");
	  event->read = NULL;
	}
    }

  if (event->write)
    {
      if (!ResetEvent (event->write))
	msg (M_WARN | M_ERRNO, "Warning: ResetEvent (write) failed in close_net_event_win32");
      if (!(flags & NE32_PERSIST_EVENT))
	{
	  if (!CloseHandle (event->write))
	    msg (M_WARN | M_ERRNO, "Warning: CloseHandle (write) failed in close_net_event_win32");
	  event->write = NULL;
	}
    }
}

/*
 * struct net_event_win32
 */

void
net_event_win32_init (struct net_event_win32 *ne)
{
  CLEAR (*ne);
  ne->sd = SOCKET_UNDEFINED;
}

void
net_event_win32_start (struct net_event_win32 *ne, long network_events, socket_descriptor_t sd)
{
  ASSERT (!socket_defined (ne->sd));
  ne->sd = sd;
  ne->event_mask = 0;
  init_net_event_win32 (&ne->handle, network_events, sd, NE32_PERSIST_EVENT|NE32_WRITE_EVENT);
}

void
net_event_win32_reset_write (struct net_event_win32 *ne)
{
  BOOL status;
  if (ne->event_mask & FD_WRITE)
    status = SetEvent (ne->handle.write);
  else
    status = ResetEvent (ne->handle.write);
  if (!status)
    msg (M_WARN | M_ERRNO, "Warning: SetEvent/ResetEvent failed in net_event_win32_reset_write");
}

void
net_event_win32_reset (struct net_event_win32 *ne)
{
  ne->event_mask |= reset_net_event_win32 (&ne->handle, ne->sd);
}

void
net_event_win32_stop (struct net_event_win32 *ne)
{
  if (net_event_win32_defined (ne))
    close_net_event_win32 (&ne->handle, ne->sd, NE32_PERSIST_EVENT);
  ne->sd = SOCKET_UNDEFINED;
  ne->event_mask = 0;
}

void
net_event_win32_close (struct net_event_win32 *ne)
{
  if (net_event_win32_defined (ne))
    close_net_event_win32 (&ne->handle, ne->sd, 0);
  net_event_win32_init (ne);
}

/*
 * Simulate *nix signals on Windows.
 *
 * Two modes:
 * (1) Console mode -- map keyboard function keys to signals
 * (2) Service mode -- map Windows event object to SIGTERM
 */

void
win32_signal_clear (struct win32_signal *ws)
{
  CLEAR (*ws);
}

void
win32_signal_open (struct win32_signal *ws,
		   int force,
		   const char *exit_event_name,
		   bool exit_event_initial_state)
{
  CLEAR (*ws);

  ws->mode = WSO_MODE_UNDEF;
  ws->in.read = INVALID_HANDLE_VALUE;
  ws->in.write = INVALID_HANDLE_VALUE;
  ws->console_mode_save = 0;
  ws->console_mode_save_defined = false;

  if (force == WSO_NOFORCE || force == WSO_FORCE_CONSOLE)
    {
      /*
       * Try to open console.
       */
      ws->in.read = GetStdHandle (STD_INPUT_HANDLE);
      if (ws->in.read != INVALID_HANDLE_VALUE)
	{
	  if (GetConsoleMode (ws->in.read, &ws->console_mode_save))
	    {
	      /* running on a console */
	      const DWORD new_console_mode = ws->console_mode_save
		& ~(ENABLE_WINDOW_INPUT
		    | ENABLE_PROCESSED_INPUT
		    | ENABLE_LINE_INPUT
		    | ENABLE_ECHO_INPUT 
		    | ENABLE_MOUSE_INPUT);

	      if (new_console_mode != ws->console_mode_save)
		{
		  if (!SetConsoleMode (ws->in.read, new_console_mode))
		    msg (M_ERR, "Error: win32_signal_open: SetConsoleMode failed");
		  ws->console_mode_save_defined = true;
		}
	      ws->mode = WSO_MODE_CONSOLE;
	    }
	  else
	    ws->in.read = INVALID_HANDLE_VALUE; /* probably running as a service */
	}
    }

  /*
   * If console open failed, assume we are running
   * as a service.
   */
  if ((force == WSO_NOFORCE || force == WSO_FORCE_SERVICE)
      && !HANDLE_DEFINED (ws->in.read) && exit_event_name)
    {
      struct security_attributes sa;

      if (!init_security_attributes_allow_all (&sa))
	msg (M_ERR, "Error: win32_signal_open: init SA failed");

      ws->in.read = CreateEvent (&sa.sa,
				 TRUE,
				 exit_event_initial_state ? TRUE : FALSE,
				 exit_event_name);
      if (ws->in.read == NULL)
	{
	  msg (M_WARN|M_ERRNO, "NOTE: CreateEvent '%s' failed", exit_event_name);
	}
      else
	{
	  if (WaitForSingleObject (ws->in.read, 0) != WAIT_TIMEOUT)
	    msg (M_FATAL, "ERROR: Exit Event ('%s') is signaled", exit_event_name);
	  else
	    ws->mode = WSO_MODE_SERVICE;
	}
    }
}

static bool
keyboard_input_available (struct win32_signal *ws)
{
  ASSERT (ws->mode == WSO_MODE_CONSOLE);
  if (HANDLE_DEFINED (ws->in.read))
    {
      DWORD n;
      if (GetNumberOfConsoleInputEvents (ws->in.read, &n))
	return n > 0;
    }
  return false;
}

static unsigned int
keyboard_ir_to_key (INPUT_RECORD *ir)
{
  if (ir->Event.KeyEvent.uChar.AsciiChar == 0)
    return ir->Event.KeyEvent.wVirtualScanCode;

  if ((ir->Event.KeyEvent.dwControlKeyState
       & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED))
      && (ir->Event.KeyEvent.wVirtualKeyCode != 18))
    return ir->Event.KeyEvent.wVirtualScanCode * 256;

  return ir->Event.KeyEvent.uChar.AsciiChar;
}

static unsigned int
win32_keyboard_get (struct win32_signal *ws)
{
  ASSERT (ws->mode == WSO_MODE_CONSOLE);
  if (HANDLE_DEFINED (ws->in.read))
    {
      INPUT_RECORD ir;
      do {
	DWORD n;
	if (!keyboard_input_available (ws))
	  return 0;
	if (!ReadConsoleInput (ws->in.read, &ir, 1, &n))
	  return 0;
      } while (ir.EventType != KEY_EVENT || ir.Event.KeyEvent.bKeyDown != TRUE);

      return keyboard_ir_to_key (&ir);
    }
  else
    return 0;
}

void
win32_signal_close (struct win32_signal *ws)
{
  if (ws->mode == WSO_MODE_SERVICE && HANDLE_DEFINED (ws->in.read))
    CloseHandle (ws->in.read);
  if (ws->console_mode_save_defined)
    {
      if (!SetConsoleMode (ws->in.read, ws->console_mode_save))
	msg (M_ERR, "Error: win32_signal_close: SetConsoleMode failed");
    }
  CLEAR (*ws);
}

/*
 * Return true if interrupt occurs in service mode.
 */
bool
win32_service_interrupt (struct win32_signal *ws)
{
  if (ws->mode == WSO_MODE_SERVICE)
    {
      if (HANDLE_DEFINED (ws->in.read)
	  && WaitForSingleObject (ws->in.read, 0) == WAIT_OBJECT_0)
	return true;
    }
  return false;
}

int
win32_signal_get (struct win32_signal *ws)
{
  int ret = 0;
  if (siginfo_static.signal_received)
    {
      ret = siginfo_static.signal_received;
    }
  else
    {
      if (ws->mode == WSO_MODE_SERVICE)
	{
	  if (win32_service_interrupt (ws))
	    ret = SIGTERM;
	}
      else if (ws->mode == WSO_MODE_CONSOLE)
	{
	  switch (win32_keyboard_get (ws))
	    {
	    case 0x3B: /* F1 -> USR1 */
	      ret = SIGUSR1;
	      break;
	    case 0x3C: /* F2 -> USR2 */
	      ret = SIGUSR2;
	      break;
	    case 0x3D: /* F3 -> HUP */
	      ret = SIGHUP;
	      break;
	    case 0x3E: /* F4 -> TERM */
	      ret = SIGTERM;
	      break;
	    }
	}
      if (ret)
	{
	  siginfo_static.signal_received = ret;
	  siginfo_static.hard = true;
	}
    }
  return ret;
}

void
win32_pause (struct win32_signal *ws)
{
  if (ws->mode == WSO_MODE_CONSOLE && HANDLE_DEFINED (ws->in.read))
    {
      int status;
      msg (M_INFO|M_NOPREFIX, "Press any key to continue...");
      do {
	status = WaitForSingleObject (ws->in.read, INFINITE);
      } while (!win32_keyboard_get (ws));
    }
}

/* window functions */

void
window_title_clear (struct window_title *wt)
{
  CLEAR (*wt);
}

void
window_title_save (struct window_title *wt)
{
  if (!wt->saved)
    {
      if (!GetConsoleTitle (wt->old_window_title, sizeof (wt->old_window_title)))
	{
	  wt->old_window_title[0] = 0;
	  wt->saved = false;
	}
      else
	wt->saved = true;
    }
}

void
window_title_restore (const struct window_title *wt)
{
  if (wt->saved)
    SetConsoleTitle (wt->old_window_title);
}

void
window_title_generate (const char *title)
{
  struct gc_arena gc = gc_new ();
  struct buffer out = alloc_buf_gc (256, &gc);
  if (!title)
    title = "";
  buf_printf (&out, "[%s] " PACKAGE_NAME " " PACKAGE_VERSION " F4:EXIT F1:USR1 F2:USR2 F3:HUP", title);
  SetConsoleTitle (BSTR (&out));
  gc_free (&gc);
}

/* semaphore functions */

void
semaphore_clear (struct semaphore *s)
{
  CLEAR (*s);
}

void
semaphore_open (struct semaphore *s, const char *name)
{
  struct security_attributes sa;

  s->locked = false;
  s->name = name;
  s->hand = NULL;

  if (init_security_attributes_allow_all (&sa))
    s->hand = CreateSemaphore(&sa.sa, 1, 1, name);

  if (s->hand == NULL)
    msg (M_WARN|M_ERRNO, "WARNING: Cannot create Win32 semaphore '%s'", name);
  else
    dmsg (D_SEMAPHORE, "Created Win32 semaphore '%s'", s->name);
}

bool
semaphore_lock (struct semaphore *s, int timeout_milliseconds)
{
  bool ret = true;

  if (s->hand)
    {
      DWORD status;
      ASSERT (!s->locked);

      dmsg (D_SEMAPHORE_LOW, "Attempting to lock Win32 semaphore '%s' prior to net shell command (timeout = %d sec)",
	   s->name,
	   timeout_milliseconds / 1000);
      status = WaitForSingleObject (s->hand, timeout_milliseconds);
      if (status == WAIT_FAILED)
	msg (M_ERR, "Wait failed on Win32 semaphore '%s'", s->name);
      ret = (status == WAIT_TIMEOUT) ? false : true;
      if (ret)
	{
	  dmsg (D_SEMAPHORE, "Locked Win32 semaphore '%s'", s->name);
	  s->locked = true;
	}
      else
	{
	  dmsg (D_SEMAPHORE, "Wait on Win32 semaphore '%s' timed out after %d milliseconds",
	       s->name,
	       timeout_milliseconds);
	}
    }
  return ret;
}

void
semaphore_release (struct semaphore *s)
{
  if (s->hand)
    {
      ASSERT (s->locked);
      dmsg (D_SEMAPHORE, "Releasing Win32 semaphore '%s'", s->name);
      if (!ReleaseSemaphore(s->hand, 1, NULL))
	msg (M_WARN | M_ERRNO, "ReleaseSemaphore failed on Win32 semaphore '%s'",
	     s->name);
      s->locked = false;
    }
}

void
semaphore_close (struct semaphore *s)
{
  if (s->hand)
    {
      if (s->locked)
	semaphore_release (s);
      dmsg (D_SEMAPHORE, "Closing Win32 semaphore '%s'", s->name);
      CloseHandle (s->hand);
      s->hand = NULL;
    }
}

/*
 * Special global semaphore used to protect network
 * shell commands from simultaneous instantiation.
 */

void
netcmd_semaphore_init (void)
{
  semaphore_open (&netcmd_semaphore, PACKAGE "_netcmd");
}

void
netcmd_semaphore_close (void)
{
  semaphore_close (&netcmd_semaphore);
}

void
netcmd_semaphore_lock (void)
{
  const int timeout_seconds = 600;
  if (!semaphore_lock (&netcmd_semaphore, timeout_seconds * 1000))
    msg (M_FATAL, "Cannot lock net command semaphore"); 
}

void
netcmd_semaphore_release (void)
{
  semaphore_release (&netcmd_semaphore);
}

/*
 * Return true if filename is safe to be used on Windows,
 * by avoiding the following reserved names:
 *
 * CON, PRN, AUX, NUL, COM1, COM2, COM3, COM4, COM5, COM6, COM7, COM8, COM9,
 * LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7, LPT8, LPT9, and CLOCK$
 *
 * See: http://msdn.microsoft.com/en-us/library/aa365247.aspx
 *  and http://msdn.microsoft.com/en-us/library/86k9f82k(VS.80).aspx
 */

static bool
cmp_prefix (const char *str, const bool n, const char *pre)
{
  size_t i = 0;

  if (!str)
    return false;

  while (true)
    {
      const int c1 = pre[i];
      int c2 = str[i];
      ++i;
      if (c1 == '\0')
	{
	  if (n)
	    {
	      if (isdigit (c2))
		c2 = str[i];
	      else
		return false;
	    }
	  return c2 == '\0' || c2 == '.';
	}
      else if (c2 == '\0')
	return false;
      if (c1 != tolower(c2))
	return false;
    }
}

bool
win_safe_filename (const char *fn)
{
  if (cmp_prefix (fn, false, "con"))
    return false;
  if (cmp_prefix (fn, false, "prn"))
    return false;
  if (cmp_prefix (fn, false, "aux"))
    return false;
  if (cmp_prefix (fn, false, "nul"))
    return false;
  if (cmp_prefix (fn, true, "com"))
    return false;
  if (cmp_prefix (fn, true, "lpt"))
    return false;
  if (cmp_prefix (fn, false, "clock$"))
    return false;
  return true;
}

/*
 * Service functions for openvpn_execve
 */

static char *
env_block (const struct env_set *es)
{
  char * force_path = "PATH=C:\\Windows\\System32;C:\\WINDOWS;C:\\WINDOWS\\System32\\Wbem";

  if (es)
    {
      struct env_item *e;
      char *ret;
      char *p;
      size_t nchars = 1;
      bool path_seen = false;
      
      for (e = es->list; e != NULL; e = e->next)
	nchars += strlen (e->string) + 1;

      nchars += strlen(force_path)+1;

      ret = (char *) malloc (nchars);
      check_malloc_return (ret);

      p = ret;
      for (e = es->list; e != NULL; e = e->next)
	{
	  if (env_allowed (e->string))
	    {
	      strcpy (p, e->string);
	      p += strlen (e->string) + 1;
	    }
	  if ( strncmp(e->string, "PATH=", 5 ) == 0 )
	    path_seen = true;
	}

      /* make sure PATH is set */
      if ( !path_seen )
	{
	  msg( M_INFO, "env_block: add %s", force_path );
	  strcpy( p, force_path );
	  p += strlen(force_path) + 1;
	}

      *p = '\0';
      return ret;
    }
  else
    return NULL;
}

static WCHAR *
wide_cmd_line (const struct argv *a, struct gc_arena *gc)
{
  size_t nchars = 1;
  size_t maxlen = 0;
  size_t i;
  struct buffer buf;
  char *work = NULL;

  if (!a)
    return NULL;

  for (i = 0; i < a->argc; ++i)
    {
      const char *arg = a->argv[i];
      const size_t len = strlen (arg);
      nchars += len + 3;
      if (len > maxlen)
	maxlen = len;
    }

  work = gc_malloc (maxlen + 1, false, gc);
  check_malloc_return (work);
  buf = alloc_buf_gc (nchars, gc);

  for (i = 0; i < a->argc; ++i)
    {
      const char *arg = a->argv[i];
      strcpy (work, arg);
      string_mod (work, CC_PRINT, CC_DOUBLE_QUOTE|CC_CRLF, '_');
      if (i)
	buf_printf (&buf, " ");
      if (string_class (work, CC_ANY, CC_SPACE))
	buf_printf (&buf, "%s", work);
      else
	buf_printf (&buf, "\"%s\"", work);
    }

  return wide_string (BSTR (&buf), gc);
}

/*
 * Attempt to simulate fork/execve on Windows
 */
int
openvpn_execve (const struct argv *a, const struct env_set *es, const unsigned int flags)
{
  int ret = -1;
  static bool exec_warn = false;

  if (a && a->argv[0])
    {
      if (openvpn_execve_allowed (flags))
	{
          struct gc_arena gc = gc_new ();
          STARTUPINFOW start_info;
          PROCESS_INFORMATION proc_info;

          char *env = env_block (es);
          WCHAR *cl = wide_cmd_line (a, &gc);
          WCHAR *cmd = wide_string (a->argv[0], &gc);

          CLEAR (start_info);
          CLEAR (proc_info);

          /* fill in STARTUPINFO struct */
          GetStartupInfoW(&start_info);
          start_info.cb = sizeof(start_info);
          start_info.dwFlags = STARTF_USESHOWWINDOW;
          start_info.wShowWindow = SW_HIDE;

          /* this allows console programs to run, and is ignored otherwise */
          DWORD proc_flags = CREATE_NO_WINDOW;

          if (CreateProcessW (cmd, cl, NULL, NULL, FALSE, proc_flags, env, NULL, &start_info, &proc_info))
            {
              DWORD exit_status = 0;
              CloseHandle (proc_info.hThread);
              WaitForSingleObject (proc_info.hProcess, INFINITE);
              if (GetExitCodeProcess (proc_info.hProcess, &exit_status))
                ret = (int)exit_status;
              else
                msg (M_WARN|M_ERRNO, "openvpn_execve: GetExitCodeProcess %S failed", cmd);
              CloseHandle (proc_info.hProcess);
            }
          else
            {
              msg (M_WARN|M_ERRNO, "openvpn_execve: CreateProcess %S failed", cmd);
            }
          free (env);
          gc_free (&gc);
        }
      else if (!exec_warn && (script_security < SSEC_SCRIPTS))
	{
	  msg (M_WARN, SCRIPT_SECURITY_WARNING);
          exec_warn = true;
	}
    }
  else
    {
      msg (M_WARN, "openvpn_execve: called with empty argv");
    }
  return ret;
}

WCHAR *
wide_string (const char* utf8, struct gc_arena *gc)
{
  int n = MultiByteToWideChar (CP_UTF8, 0, utf8, -1, NULL, 0);
  WCHAR *ucs16 = gc_malloc (n * sizeof (WCHAR), false, gc);
  MultiByteToWideChar (CP_UTF8, 0, utf8, -1, ucs16, n);
  return ucs16;
}

/*
 * call ourself in another process
 */
void
fork_to_self (const char *cmdline)
{
  STARTUPINFO start_info;
  PROCESS_INFORMATION proc_info;
  char self_exe[256];
  char *cl = string_alloc (cmdline, NULL);
  DWORD status;

  CLEAR (start_info);
  CLEAR (proc_info);
  CLEAR (self_exe);

  status = GetModuleFileName (NULL, self_exe, sizeof(self_exe));
  if (status == 0 || status == sizeof(self_exe))
    {
      msg (M_WARN|M_ERRNO, "fork_to_self: CreateProcess failed: cannot get module name via GetModuleFileName");
      goto done;
    }

  /* fill in STARTUPINFO struct */
  GetStartupInfo(&start_info);
  start_info.cb = sizeof(start_info);
  start_info.dwFlags = STARTF_USESHOWWINDOW;
  start_info.wShowWindow = SW_HIDE;

  if (CreateProcess (self_exe, cl, NULL, NULL, FALSE, 0, NULL, NULL, &start_info, &proc_info))
    {
      CloseHandle (proc_info.hThread);
      CloseHandle (proc_info.hProcess);
    }
  else
    {
      msg (M_WARN|M_ERRNO, "fork_to_self: CreateProcess failed: %s", cmdline);
    }

 done:
  free (cl);
}

char *
get_win_sys_path (void)
{
  ASSERT (win_sys_path);
  return win_sys_path;
}

void
set_win_sys_path (const char *newpath, struct env_set *es)
{
  free (win_sys_path);
  win_sys_path = string_alloc (newpath, NULL);
  setenv_str (es, SYS_PATH_ENV_VAR_NAME, win_sys_path); /* route.exe needs this */
}

void
set_win_sys_path_via_env (struct env_set *es)
{
  char buf[256];
  DWORD status = GetEnvironmentVariable (SYS_PATH_ENV_VAR_NAME, buf, sizeof(buf));
  if (!status)
    msg (M_ERR, "Cannot find environmental variable %s", SYS_PATH_ENV_VAR_NAME);
  if (status > sizeof (buf) - 1)
    msg (M_FATAL, "String overflow attempting to read environmental variable %s", SYS_PATH_ENV_VAR_NAME);
  set_win_sys_path (buf, es);
}


const char *
win_get_tempdir()
{
  static char buf[MAX_PATH];
  char *tmpdir = buf;

  CLEAR(buf);

  if (!GetTempPath(sizeof(buf),buf)) {
    /* Warn if we can't find a valid temporary directory, which should
     * be unlikely.
     */
    msg (M_WARN, "Could not find a suitable temporary directory."
         " (GetTempPath() failed).  Consider to use --tmp-dir");
    tmpdir = NULL;
  }
  return tmpdir;
}
#endif
