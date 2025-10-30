#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "push.h"
#include "buffer.h"

#ifdef ENABLE_MANAGEMENT
#include "multi.h"
#include "ssl_util.h"
#endif

int
process_push_update(struct context *c, struct options *o, unsigned int permission_mask,
                    unsigned int *option_types_found, struct buffer *buf, bool msg_sender)
{
    int ret = PUSH_MSG_ERROR;
    const int ch = buf_read_u8(buf);
    if (ch == ',')
    {
        if (apply_push_options(c, o, buf, permission_mask, option_types_found, c->c2.es,
                               true))
        {
            switch (o->push_continuation)
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
static size_t
find_first_comma_of_next_bundle(const char *str, size_t ix)
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
    size_t src_len = strlen(src);
    size_t con_len = continuation ? strlen(continuation) : 0;
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

/* It split the messagge (if necessary) and fill msgs with the message chunks.
 * Return `false` on failure an `true` on success.
 */
static bool
message_splitter(const char *s, struct buffer_list *msgs, struct gc_arena *gc, const size_t safe_cap)
{
    if (!s || !*s)
    {
        return false;
    }

    char *str = gc_strdup(s, gc);
    size_t i = 0;

    while (*str)
    {
        /* + ',' - '/0' */
        if (strlen(str) > safe_cap)
        {
            size_t ci = find_first_comma_of_next_bundle(str, safe_cap);
            if (!ci)
            {
                /* if no commas were found go to fail, do not send any message */
                return false;
            }
            str[ci] = '\0';
            /* copy from i to (ci -1) */
            struct buffer tmp = forge_msg(str, ",push-continuation 2", gc);
            buffer_list_push(msgs, BSTR(&tmp));
            i = ci + 1;
        }
        else
        {
            if (msgs->head)
            {
                struct buffer tmp = forge_msg(str, ",push-continuation 1", gc);
                buffer_list_push(msgs, BSTR(&tmp));
            }
            else
            {
                struct buffer tmp = forge_msg(str, NULL, gc);
                buffer_list_push(msgs, BSTR(&tmp));
            }
            i = strlen(str);
        }
        str = &str[i];
    }
    return true;
}

/* send the message(s) prepared to one single client */
static bool
send_single_push_update(struct multi_context *m, struct multi_instance *mi, struct buffer_list *msgs)
{
    if (!msgs->head)
    {
        return false;
    }

    unsigned int option_types_found = 0;
    struct context *c = &mi->context;
    struct options o;
    CLEAR(o);

    /* Set canary values to detect ifconfig options in push-update messages.
     * These placeholder strings will be overwritten to NULL by the option
     * parser if -ifconfig or -ifconfig-ipv6 options are present in the
     * push-update.
     */
    const char *canary = "canary";
    o.ifconfig_local = canary;
    o.ifconfig_ipv6_local = canary;

    struct buffer_entry *e = msgs->head;
    while (e)
    {
        if (!send_control_channel_string(c, BSTR(&e->buf), D_PUSH))
        {
            return false;
        }

        /* After sending the control message, we parse it, miming the behavior
         * of `process_incoming_push_msg()` and we fill an empty `options` struct
         * with the new options. If an `ifconfig_local` or `ifconfig_ipv6_local`
         * options is found we update the vhash accordingly, so that the pushed
         * ifconfig/ifconfig-ipv6 options can actually work.
         * If we don't do that, packets arriving from the client with the
         * new address will be rejected and packets for the new address
         * will not be routed towards the client.
         * Using `buf_string_compare_advance()` we mimic the behavior
         * inside `process_incoming_push_msg()`. However, we don't need
         * to check the return value here because we just want to `advance`,
         * meaning we skip the `push_update_cmd' we added earlier.
         * Also we need to make a temporary copy so we can buf_advance()
         * without modifying original buffer.
         */
        struct buffer tmp_msg = e->buf;
        buf_string_compare_advance(&tmp_msg, push_update_cmd);
        unsigned int permission_mask = pull_permission_mask(c);
        if (process_push_update(c, &o, permission_mask, &option_types_found, &tmp_msg, true) == PUSH_MSG_ERROR)
        {
            msg(M_WARN, "Failed to process push update message sent to client ID: %u", c->c2.tls_multi->peer_id);
        }
        e = e->next;
    }

    if (option_types_found & OPT_P_UP)
    {
        /* -ifconfig */
        if (!o.ifconfig_local && mi->context.c2.push_ifconfig_defined)
        {
            unlearn_ifconfig(m, mi);
        }
        /* -ifconfig-ipv6 */
        if (!o.ifconfig_ipv6_local && mi->context.c2.push_ifconfig_ipv6_defined)
        {
            unlearn_ifconfig_ipv6(m, mi);
        }

        if (o.ifconfig_local && !strcmp(o.ifconfig_local, canary))
        {
            o.ifconfig_local = NULL;
        }
        if (o.ifconfig_ipv6_local && !strcmp(o.ifconfig_ipv6_local, canary))
        {
            o.ifconfig_ipv6_local = NULL;
        }

        /* new ifconfig or new ifconfig-ipv6 */
        update_vhash(m, mi, o.ifconfig_local, o.ifconfig_ipv6_local);
    }

    return true;
}

/* Return true if the client supports push-update */
static bool
support_push_update(struct multi_instance *mi)
{
    ASSERT(mi->context.c2.tls_multi);
    const unsigned int iv_proto_peer = extract_iv_proto(mi->context.c2.tls_multi->peer_info);
    if (!(iv_proto_peer & IV_PROTO_PUSH_UPDATE))
    {
        return false;
    }

    return true;
}

/**
 * @brief A function to send a PUSH_UPDATE control message from server to client(s).
 *
 * @param m the multi_context, contains all the clients connected to this server.
 * @param target the target to which to send the message. It should be:
 * `NULL` if `type == UPT_BROADCAST`,
 * a `mroute_addr *` if `type == UPT_BY_ADDR`,
 * a `char *` if `type == UPT_BY_CN`,
 * an `unsigned long *` if `type == UPT_BY_CID`.
 * @param msg a string containing the options to send.
 * @param type the way to address the message (broadcast, by cid, by cn, by address).
 * @param push_bundle_size the maximum size of a bundle of pushed option. Just use PUSH_BUNDLE_SIZE macro.
 * @return The number of clients to which the message was sent. Might return < 0 in case of error.
 */
static int
send_push_update(struct multi_context *m, const void *target, const char *msg, const push_update_type type, const size_t push_bundle_size)
{
    if (dco_enabled(&m->top.options))
    {
        msg(M_WARN, "WARN: PUSH_UPDATE messages cannot currently be sent while DCO is enabled."
                    " To send a PUSH_UPDATE message, be sure to use the --disable-dco option.");
        return 0;
    }

    if (!msg || !*msg || !m || (!target && type != UPT_BROADCAST))
    {
        return -EINVAL;
    }

    struct gc_arena gc = gc_new();
    /* extra space for possible trailing ifconfig and push-continuation */
    const size_t extra = 84 + sizeof(push_update_cmd);
    /* push_bundle_size is the maximum size of a message, so if the message
     * we want to send exceeds that size we have to split it into smaller messages */
    ASSERT(push_bundle_size > extra);
    const size_t safe_cap = push_bundle_size - extra;
    struct buffer_list *msgs = buffer_list_new();

    if (!message_splitter(msg, msgs, &gc, safe_cap))
    {
        buffer_list_free(msgs);
        gc_free(&gc);
        return -EINVAL;
    }

    if (type == UPT_BY_CID)
    {
        struct multi_instance *mi = lookup_by_cid(m, *((unsigned long *)target));

        if (!mi)
        {
            buffer_list_free(msgs);
            gc_free(&gc);
            return -ENOENT;
        }

        if (!support_push_update(mi))
        {
            msg(M_CLIENT, "PUSH_UPDATE: not sending message to unsupported peer with ID: %u", mi->context.c2.tls_multi->peer_id);
            buffer_list_free(msgs);
            gc_free(&gc);
            return 0;
        }

        if (!mi->halt
            && send_single_push_update(m, mi, msgs))
        {
            buffer_list_free(msgs);
            gc_free(&gc);
            return 1;
        }
        else
        {
            buffer_list_free(msgs);
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

        if (curr_mi->halt || !support_push_update(curr_mi))
        {
            continue;
        }

        /* Type is UPT_BROADCAST so we update every client */
        if (!send_single_push_update(m, curr_mi, msgs))
        {
            msg(M_CLIENT, "ERROR: Peer ID: %u has not been updated", curr_mi->context.c2.tls_multi->peer_id);
            continue;
        }
        count++;
    }

    hash_iterator_free(&hi);
    buffer_list_free(msgs);
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
