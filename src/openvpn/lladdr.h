/*
 * Support routine for configuring link layer address 
 */

#include "misc.h"

int set_lladdr(const char *ifname, const char *lladdr,
		const struct env_set *es);
