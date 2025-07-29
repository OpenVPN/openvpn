#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "push.h"

int
process_incoming_push_update(struct context *c,
                             unsigned int permission_mask,
                             unsigned int *option_types_found,
                             struct buffer *buf)
{
    int ret = PUSH_MSG_ERROR;
    const uint8_t ch = buf_read_u8(buf);
    if (ch == ',')
    {
        if (apply_push_options(c,
                               &c->options,
                               buf,
                               permission_mask,
                               option_types_found,
                               c->c2.es,
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
    }
    else if (ch == '\0')
    {
        ret = PUSH_MSG_UPDATE;
    }

    return ret;
}
