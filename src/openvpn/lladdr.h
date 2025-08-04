/*
 * Support routine for configuring link layer address
 */

#include "misc.h"
#include "networking.h"

int set_lladdr(openvpn_net_ctx_t *ctx, const char *ifname, const char *lladdr,
               const struct env_set *es);
