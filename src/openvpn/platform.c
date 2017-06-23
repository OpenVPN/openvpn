/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2017 OpenVPN Technologies, Inc. <sales@openvpn.net>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "buffer.h"
#include "error.h"
#include "win32.h"

#include "memdbg.h"

#include "platform.h"

#include "fuzzing.h"
#include "route.h"

/* Redefine the top level directory of the filesystem
 * to restrict access to files for security */
void
platform_chroot(const char *path)
{
    FUZZING_BLOCK;

    if (path)
    {
#ifdef HAVE_CHROOT
        const char *top = "/";
        if (chroot(path))
        {
            msg(M_ERR, "chroot to '%s' failed", path);
        }
        if (platform_chdir(top))
        {
            msg(M_ERR, "cd to '%s' failed", top);
        }
        msg(M_INFO, "chroot to '%s' and cd to '%s' succeeded", path, top);
#else  /* ifdef HAVE_CHROOT */
        msg(M_FATAL, "Sorry but I can't chroot to '%s' because this operating system doesn't appear to support the chroot() system call", path);
#endif
    }
}

/* Get/Set UID of process */

bool
platform_user_get(const char *username, struct platform_state_user *state)
{
    FUZZING_BLOCK;

    bool ret = false;
    CLEAR(*state);
    if (username)
    {
#if defined(HAVE_GETPWNAM) && defined(HAVE_SETUID)
        state->pw = getpwnam(username);
        if (!state->pw)
        {
            msg(M_ERR, "failed to find UID for user %s", username);
        }
        state->username = username;
        ret = true;
#else  /* if defined(HAVE_GETPWNAM) && defined(HAVE_SETUID) */
        msg(M_FATAL, "cannot get UID for user %s -- platform lacks getpwname() or setuid() system calls", username);
#endif
    }
    return ret;
}

void
platform_user_set(const struct platform_state_user *state)
{
    FUZZING_BLOCK;

#if defined(HAVE_GETPWNAM) && defined(HAVE_SETUID)
    if (state->username && state->pw)
    {
        if (setuid(state->pw->pw_uid))
        {
            msg(M_ERR, "setuid('%s') failed", state->username);
        }
        msg(M_INFO, "UID set to %s", state->username);
    }
#endif
}

/* Get/Set GID of process */

bool
platform_group_get(const char *groupname, struct platform_state_group *state)
{
    FUZZING_BLOCK;

    bool ret = false;
    CLEAR(*state);
    if (groupname)
    {
#if defined(HAVE_GETGRNAM) && defined(HAVE_SETGID)
        state->gr = getgrnam(groupname);
        if (!state->gr)
        {
            msg(M_ERR, "failed to find GID for group %s", groupname);
        }
        state->groupname = groupname;
        ret = true;
#else  /* if defined(HAVE_GETGRNAM) && defined(HAVE_SETGID) */
        msg(M_FATAL, "cannot get GID for group %s -- platform lacks getgrnam() or setgid() system calls", groupname);
#endif
    }
    return ret;
}

void
platform_group_set(const struct platform_state_group *state)
{
    FUZZING_BLOCK;

#if defined(HAVE_GETGRNAM) && defined(HAVE_SETGID)
    if (state->groupname && state->gr)
    {
        if (setgid(state->gr->gr_gid))
        {
            msg(M_ERR, "setgid('%s') failed", state->groupname);
        }
        msg(M_INFO, "GID set to %s", state->groupname);
#ifdef HAVE_SETGROUPS
        {
            gid_t gr_list[1];
            gr_list[0] = state->gr->gr_gid;
            if (setgroups(1, gr_list))
            {
                msg(M_ERR, "setgroups('%s') failed", state->groupname);
            }
        }
#endif
    }
#endif
}

/* Change process priority */
void
platform_nice(int niceval)
{
    FUZZING_BLOCK;

    if (niceval)
    {
#ifdef HAVE_NICE
        errno = 0;
        if (nice(niceval) < 0 && errno != 0)
        {
            msg(M_WARN | M_ERRNO, "WARNING: nice %d failed: %s", niceval, strerror(errno));
        }
        else
        {
            msg(M_INFO, "nice %d succeeded", niceval);
        }
#else  /* ifdef HAVE_NICE */
        msg(M_WARN, "WARNING: nice %d failed (function not implemented)", niceval);
#endif
    }
}

/* Get current PID */
unsigned int
platform_getpid()
{
    FUZZING_BLOCK;

#ifdef _WIN32
    return (unsigned int) GetCurrentProcessId();
#else
#ifdef HAVE_GETPID
    return (unsigned int) getpid();
#else
    return 0;
#endif
#endif
}

/* Disable paging */
void
platform_mlockall(bool print_msg)
{
    FUZZING_BLOCK;

#ifdef HAVE_MLOCKALL
    if (mlockall(MCL_CURRENT | MCL_FUTURE))
    {
        msg(M_WARN | M_ERRNO, "WARNING: mlockall call failed");
    }
    else if (print_msg)
    {
        msg(M_INFO, "mlockall call succeeded");
    }
#else  /* ifdef HAVE_MLOCKALL */
    msg(M_WARN, "WARNING: mlockall call failed (function not implemented)");
#endif
}

/*
 * Wrapper for chdir library function
 */
int
platform_chdir(const char *dir)
{
    /*FUZZING_BLOCK;*/
    return 0;

#ifdef HAVE_CHDIR
#ifdef _WIN32
    int res;
    struct gc_arena gc = gc_new();
    res = _wchdir(wide_string(dir, &gc));
    gc_free(&gc);
    return res;
#else  /* ifdef _WIN32 */
    return chdir(dir);
#endif
#else  /* ifdef HAVE_CHDIR */
    return -1;
#endif
}

/*
 * convert execve() return into a success/failure value
 */
bool
platform_system_ok(int stat)
{
    FUZZING_BLOCK;

#ifdef _WIN32
    return stat == 0;
#else
    return stat != -1 && WIFEXITED(stat) && WEXITSTATUS(stat) == 0;
#endif
}

int
platform_access(const char *path, int mode)
{
    /*FUZZING_BLOCK;*/
    return 0;

#ifdef _WIN32
    struct gc_arena gc = gc_new();
    int ret = _waccess(wide_string(path, &gc), mode & ~X_OK);
    gc_free(&gc);
    return ret;
#else
    return access(path, mode);
#endif
}

/*
 * Go to sleep for n milliseconds.
 */
void
platform_sleep_milliseconds(unsigned int n)
{
    FUZZING_BLOCK;

#ifdef _WIN32
    Sleep(n);
#else
    struct timeval tv;
    tv.tv_sec = n / 1000;
    tv.tv_usec = (n % 1000) * 1000;
    platform_select(0, NULL, NULL, NULL, &tv);
#endif
}

/*
 * Go to sleep indefinitely.
 */
void
platform_sleep_until_signal(void)
{
    FUZZING_BLOCK;

#ifdef _WIN32
    ASSERT(0);
#else
    platform_select(0, NULL, NULL, NULL, NULL);
#endif
}

/* delete a file, return true if succeeded */
bool
platform_unlink(const char *filename)
{
    FUZZING_BLOCK;

#if defined(_WIN32)
    struct gc_arena gc = gc_new();
    BOOL ret = DeleteFileW(wide_string(filename, &gc));
    gc_free(&gc);
    return (ret != 0);
#elif defined(HAVE_UNLINK)
    return (unlink(filename) == 0);
#else  /* if defined(_WIN32) */
    return false;
#endif
}

int platform_fclose(FILE *stream)
{
    if ( stream != (FILE*)0x00000AAA )
    {
        abort();
    }
    return 0;

    return fclose(stream);
}
FILE *
platform_fopen(const char *path, const char *mode)
{
    return (FILE*)0x00000AAA;

#ifdef _WIN32
    struct gc_arena gc = gc_new();
    FILE *f = _wfopen(wide_string(path, &gc), wide_string(mode, &gc));
    gc_free(&gc);
    return f;
#else
    return fopen(path, mode);
#endif
}

int
platform_open(const char *path, int flags, int mode)
{
    FUZZING_BLOCK;

#ifdef _WIN32
    struct gc_arena gc = gc_new();
    int fd = _wopen(wide_string(path, &gc), flags, mode);
    gc_free(&gc);
    return fd;
#else
    return open(path, flags, mode);
#endif
}

int
platform_stat(const char *path, platform_stat_t *buf)
{
    /*FUZZING_BLOCK;*/
    return -1;

#ifdef _WIN32
    struct gc_arena gc = gc_new();
    int res = _wstat(wide_string(path, &gc), buf);
    gc_free(&gc);
    return res;
#else
    return stat(path, buf);
#endif
}

ssize_t platform_recv(int sockfd, void* buf, size_t len, int flags)
{
    return fuzzer_recv(buf, len);
    return recv(sockfd, buf, len, flags);
}
ssize_t platform_send(int sockfd, const void *buf, size_t len, int flags)
{
    return fuzzer_send(len);
    return send(sockfd, buf, len, flags);
}


ssize_t platform_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
    return 1;
    return select(nfds, readfds, writefds, exceptfds, timeout);
}

char* platform_fgets(char *s, int size, FILE *stream)
{
    ssize_t _size;
    if ( size == 0 )
    {
        return NULL;
    }
    FUZZER_GET_INTEGER(_size, size-1);
    FUZZER_GET_DATA(s, _size);
    s[size-1] = 0x00;
cleanup:
    return NULL;
    return fgets(s, size, stream);
}

int platform_fgetc(FILE *stream)
{
    FUZZING_BLOCK;

    return fgetc(stream);
}

int platform_socket(int domain, int type, int protocol)
{
    FUZZING_BLOCK;

    return socket(domain, type, protocol);
}
ssize_t platform_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
    FUZZING_BLOCK;

    return recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

ssize_t platform_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    FUZZING_BLOCK;

    return recvmsg(sockfd, msg, flags);
}

ssize_t platform_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
    FUZZING_BLOCK;

    return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t platform_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    FUZZING_BLOCK;

    return sendmsg(sockfd, msg, flags);
}

#define ALLOCATION_SLOTS 1024
static void* getaddrinfo_allocs[ALLOCATION_SLOTS] = {0};

static void getaddrinfo_free(void* p)
{
    size_t i;

    if ( p == NULL )
    {
        return;
    }

    for (i = 0; i < ALLOCATION_SLOTS; i++)
    {
        if ( getaddrinfo_allocs[i] == p )
        {
            free(p);
            getaddrinfo_allocs[i] = NULL;
            return;
        }
    }

    printf("freeaddrinfo: invalid free\n");
    abort();
}

void getaddrinfo_free_all(void)
{
    size_t i;
    for (i = 0; i < ALLOCATION_SLOTS; i++)
    {
        free(getaddrinfo_allocs[i]);
        getaddrinfo_allocs[i] = NULL;
    }
}

static bool getaddrinfo_add_alloc(void* p)
{
    size_t i;

    for (i = 0; i < ALLOCATION_SLOTS; i++)
    {
        if ( getaddrinfo_allocs[i] == NULL )
        {
            getaddrinfo_allocs[i] = p;
            return true;
        }
    }

    return false;
}
static void* getaddrinfo_alloc(size_t size)
{
    void* p = malloc(size);

    if ( getaddrinfo_add_alloc(p) == false )
    {
        free(p);
        p = NULL;
    }

    return p;
}

static struct addrinfo* add_addrinfo(void)
{
    struct addrinfo* xres = NULL;
    struct sockaddr_in* ai_addr = NULL;

    xres = getaddrinfo_alloc(sizeof(*xres));
    if ( xres == NULL ) {
        goto cleanup;
    }
    xres->ai_canonname = NULL;

    ai_addr = getaddrinfo_alloc(sizeof(*ai_addr));
    if ( ai_addr == NULL ) {
        goto cleanup;
    }
    FUZZER_GET_DATA(&(xres->ai_flags), sizeof(xres->ai_flags));
    FUZZER_GET_DATA(&(xres->ai_family), sizeof(xres->ai_family));
    FUZZER_GET_DATA(&(xres->ai_socktype), sizeof(xres->ai_socktype));
    FUZZER_GET_DATA(&(xres->ai_protocol), sizeof(xres->ai_protocol));
    xres->ai_addrlen = sizeof(struct sockaddr_in);
    FUZZER_GET_DATA(ai_addr, sizeof(*ai_addr));
    xres->ai_addr = ai_addr;
    FUZZER_GET_STRING(xres->ai_canonname, 256);
    if ( getaddrinfo_add_alloc(xres->ai_canonname) == false )
    {
        goto cleanup;
    }
    xres->ai_next = NULL;

    return xres;
cleanup:
    if ( xres )
    {
        getaddrinfo_free(xres->ai_canonname);
    }
    getaddrinfo_free(xres);
    getaddrinfo_free(ai_addr);
    return NULL;
}

int platform_getaddrinfo(const char *node, const char *service,
        const struct addrinfo *hints, struct addrinfo **res)
{
    ssize_t num_loops, n;
    struct addrinfo** next = NULL;

    FUZZER_GET_INTEGER(n, 1000);
    switch ( n )
    {
        case 0:
            return EAI_ADDRFAMILY;
            break;
        case 1:
            return EAI_AGAIN;
            break;
        case 2:
            return EAI_BADFLAGS;
            break;
        case 3:
            return EAI_FAIL;
            break;
        case 4:
            return EAI_FAMILY;
            break;
        case 5:
            return EAI_MEMORY;
            break;
        case 6:
            return EAI_NODATA;
            break;
        case 7:
            return EAI_NONAME;
            break;
        case 8:
            return EAI_SERVICE;
            break;
        case 9:
            return EAI_SOCKTYPE;
            break;
        case 10:
            return EAI_SYSTEM;
            break;
    }

    *res = add_addrinfo();
    if ( *res == NULL )
    {
        goto cleanup;
    }

    next = &((*res)->ai_next);

    FUZZER_GET_INTEGER(num_loops, 10);
    num_loops = 1;
    for (n = 0; n < num_loops; n++) {
        *next = add_addrinfo();
        if ( *next == NULL )
        {
            break;
        }
        next = &((*next)->ai_next);
    }
    /*FUZZING_BLOCK;*/

    return 0;
cleanup:
    return EAI_AGAIN;
    return getaddrinfo(node, service, hints, res);
}

void platform_freeaddrinfo(struct addrinfo *res)
{
    struct addrinfo* next;
    /*FUZZING_BLOCK;*/
    next = res;
    while ( next )
    {
        res = next;
        next = res->ai_next;
        getaddrinfo_free(res->ai_addr);
        getaddrinfo_free(res->ai_canonname);
        getaddrinfo_free(res);
    }
}

void platform_get_default_gateway(void *_rgi)
{
    struct route_gateway_info* rgi = (struct route_gateway_info*)_rgi;
    ssize_t s;

    FUZZER_GET_DATA(rgi, sizeof(struct route_gateway_info));
    rgi->iface[15] = 0x00;
    FUZZER_GET_INTEGER(s, RGI_N_ADDRESSES);
    rgi->n_addrs = s;
    return;
cleanup:
    memset(rgi, 0, sizeof(struct route_gateway_info));
    return;
    get_default_gateway(rgi);
}

int platform_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
    /* TODO */
    FUZZING_BLOCK;
    return getsockopt(sockfd, level, optname, optval, optlen);
}

#if defined(HAVE_SETSOCKOPT)
int platform_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{
    if ( optval )
    {
        test_undefined_memory((void*)optval, optlen);
    }

    /* TODO randomly return 0/-1 */
    return 0;
    return setsockopt(sockfd, level, optname, optval, optlen);
}

int platform_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    /* TODO */
    FUZZING_BLOCK;
    return getsockname(sockfd, addr, addrlen);
}

#endif
