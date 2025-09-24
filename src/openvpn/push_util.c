#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "push.h"
#include "buffer.h"

#ifdef ENABLE_MANAGEMENT
#include "multi.h"
#endif

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#endif

int
process_incoming_push_update(struct context *c, unsigned int permission_mask,
                             unsigned int *option_types_found, struct buffer *buf,
                             bool msg_sender)
{
    int ret = PUSH_MSG_ERROR;
    const uint8_t ch = buf_read_u8(buf);
    if (ch == ',')
    {
        if (apply_push_options(c, &c->options, buf, permission_mask, option_types_found, c->c2.es,
                               true))
        {
            switch (c->options.push_continuation)
            {
                case 0:
                case 1:
                    ret = PUSH_MSG_UPDATE;
                    break;

                case 2:
                    ret = PUSH_MSG_CONTINUATION;
                    break;
            }
        }
        else if (!msg_sender)
        {
            throw_signal_soft(SIGUSR1, "Offending option received from server");
        }
    }
    else if (ch == '\0')
    {
        ret = PUSH_MSG_UPDATE;
    }

    return ret;
}

#ifdef ENABLE_MANAGEMENT
/**
 * Return index of last `,` or `0` if it didn't find any.
 * If there is a comma at index `0` it's an error anyway
 */
static int
find_first_comma_of_next_bundle(const char *str, int ix)
{
    while (ix > 0)
    {
        if (str[ix] == ',')
        {
            return ix;
        }
        ix--;
    }
    return 0;
}

/* Allocate memory and assemble the final message */
static struct buffer
forge_msg(const char *src, const char *continuation, struct gc_arena *gc)
{
    int src_len = strlen(src);
    int con_len = continuation ? strlen(continuation) : 0;
    struct buffer buf = alloc_buf_gc(src_len + sizeof(push_update_cmd) + con_len + 2, gc);

    buf_printf(&buf, "%s,%s%s", push_update_cmd, src, continuation ? continuation : "");

    return buf;
}

static char *
gc_strdup(const char *src, struct gc_arena *gc)
{
    char *ret = gc_malloc((strlen(src) + 1) * sizeof(char), true, gc);

    strcpy(ret, src);
    return ret;
}

/* It split the messagge (if necessay) and fill msgs with the message chunks.
 * Return `false` on failure an `true` on success.
 */
static bool
message_splitter(const char *s, struct buffer *msgs, struct gc_arena *gc, const int safe_cap)
{
    if (!s || !*s)
    {
        return false;
    }

    char *str = gc_strdup(s, gc);
    int i = 0;
    int im = 0;

    while (*str)
    {
        /* + ',' - '/0' */
        if (strlen(str) > safe_cap)
        {
            int ci = find_first_comma_of_next_bundle(str, safe_cap);
            if (!ci)
            {
                /* if no commas were found go to fail, do not send any message */
                return false;
            }
            str[ci] = '\0';
            /* copy from i to (ci -1) */
            msgs[im] = forge_msg(str, ",push-continuation 2", gc);
            i = ci + 1;
        }
        else
        {
            if (im)
            {
                msgs[im] = forge_msg(str, ",push-continuation 1", gc);
            }
            else
            {
                msgs[im] = forge_msg(str, NULL, gc);
            }
            i = strlen(str);
        }
        str = &str[i];
        im++;
    }
    return true;
}

/* send the message(s) prepared to one single client */
static bool
send_single_push_update(struct context *c, struct buffer *msgs, unsigned int *option_types_found)
{
    if (!msgs[0].data || !*(msgs[0].data))
    {
        return false;
    }
    int i = -1;

    while (msgs[++i].data && *(msgs[i].data))
    {
        if (!send_control_channel_string(c, BSTR(&msgs[i]), D_PUSH))
        {
            return false;
        }

        /* After sending the control message, we update the options
         * server-side in the client's context so pushed options like
         * ifconfig/ifconfig-ipv6 can actually work.
         * If we don't do that, packets arriving from the client with the
         * new address will be rejected and packets for the new address
         * will not be routed towards the client.
         * For the same reason we later update the vhash too in
         * `send_push_update()` function.
         * Using `buf_string_compare_advance()` we mimic the behavior
         * inside `process_incoming_push_msg()`. However, we don't need
         * to check the return value here because we just want to `advance`,
         * meaning we skip the `push_update_cmd' we added earlier.
         */
        buf_string_compare_advance(&msgs[i], push_update_cmd);
        if (process_incoming_push_update(c, pull_permission_mask(c), option_types_found, &msgs[i], true) == PUSH_MSG_ERROR)
        {
            msg(M_WARN, "Failed to process push update message sent to client ID: %u",
                c->c2.tls_multi ? c->c2.tls_multi->peer_id : UINT32_MAX);
            continue;
        }
        c->options.push_option_types_found |= *option_types_found;
        if (!options_postprocess_pull(&c->options, c->c2.es))
        {
            msg(M_WARN, "Failed to post-process push update message sent to client ID: %u",
                c->c2.tls_multi ? c->c2.tls_multi->peer_id : UINT32_MAX);
        }
    }
    return true;
}

int
send_push_update(struct multi_context *m, const void *target, const char *msg, const push_update_type type, const int push_bundle_size)
{
    if (!msg || !*msg || !m
        || (!target && type != UPT_BROADCAST))
    {
        return -EINVAL;
    }

    struct gc_arena gc = gc_new();
    /* extra space for possible trailing ifconfig and push-continuation */
    const int extra = 84 + sizeof(push_update_cmd);
    /* push_bundle_size is the maximum size of a message, so if the message
     * we want to send exceeds that size we have to split it into smaller messages */
    const int safe_cap = push_bundle_size - extra;
    int msgs_num = (strlen(msg) / safe_cap) + ((strlen(msg) % safe_cap) != 0);
    struct buffer *msgs = gc_malloc((msgs_num + 1) * sizeof(struct buffer), true, &gc);

    unsigned int option_types_found = 0;

    msgs[msgs_num].data = NULL;
    if (!message_splitter(msg, msgs, &gc, safe_cap))
    {
        gc_free(&gc);
        return -EINVAL;
    }

    if (type == UPT_BY_CID)
    {
        struct multi_instance *mi = lookup_by_cid(m, *((unsigned long *)target));

        if (!mi)
        {
            return -ENOENT;
        }

        const char *old_ip = mi->context.options.ifconfig_local;
        const char *old_ipv6 = mi->context.options.ifconfig_ipv6_local;
        if (!mi->halt
            && send_single_push_update(&mi->context, msgs, &option_types_found))
        {
            if (option_types_found & OPT_P_UP)
            {
                update_vhash(m, mi, old_ip, old_ipv6);
            }
            gc_free(&gc);
            return 1;
        }
        else
        {
            gc_free(&gc);
            return 0;
        }
    }

    int count = 0;
    struct hash_iterator hi;
    const struct hash_element *he;

    hash_iterator_init(m->iter, &hi);
    while ((he = hash_iterator_next(&hi)))
    {
        struct multi_instance *curr_mi = he->value;

        if (curr_mi->halt)
        {
            continue;
        }

        /* Type is UPT_BROADCAST so we update every client */
        option_types_found = 0;
        const char *old_ip = curr_mi->context.options.ifconfig_local;
        const char *old_ipv6 = curr_mi->context.options.ifconfig_ipv6_local;
        if (!send_single_push_update(&curr_mi->context, msgs, &option_types_found))
        {
            msg(M_CLIENT, "ERROR: Peer ID: %u has not been updated",
                curr_mi->context.c2.tls_multi ? curr_mi->context.c2.tls_multi->peer_id : UINT32_MAX);
            continue;
        }
        if (option_types_found & OPT_P_UP)
        {
            update_vhash(m, curr_mi, old_ip, old_ipv6);
        }
        count++;
    }

    hash_iterator_free(&hi);
    gc_free(&gc);
    return count;
}

#define RETURN_UPDATE_STATUS(n_sent)                                  \
    do                                                                \
    {                                                                 \
        if ((n_sent) > 0)                                             \
        {                                                             \
            msg(M_CLIENT, "SUCCESS: %d client(s) updated", (n_sent)); \
            return true;                                              \
        }                                                             \
        else                                                          \
        {                                                             \
            msg(M_CLIENT, "ERROR: no client updated");                \
            return false;                                             \
        }                                                             \
    } while (0)


bool
management_callback_send_push_update_broadcast(void *arg, const char *options)
{
    int n_sent = send_push_update(arg, NULL, options, UPT_BROADCAST, PUSH_BUNDLE_SIZE);

    RETURN_UPDATE_STATUS(n_sent);
}

bool
management_callback_send_push_update_by_cid(void *arg, unsigned long cid, const char *options)
{
    int n_sent = send_push_update(arg, &cid, options, UPT_BY_CID, PUSH_BUNDLE_SIZE);

    RETURN_UPDATE_STATUS(n_sent);
}
#endif /* ifdef ENABLE_MANAGEMENT */

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
