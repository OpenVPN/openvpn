/*
 *  Generic interface to platform specific networking code
 *
 *  Copyright (C) 2016-2021 Antonio Quartulli <a@unstable.cc>
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


#ifndef NETWORKING_IP_H_
#define NETWORKING_IP_H_

#include "env_set.h"

typedef char openvpn_net_iface_t;

struct openvpn_net_ctx
{
    struct env_set *es;
    struct gc_arena gc;
};

typedef struct openvpn_net_ctx openvpn_net_ctx_t;

#endif /* NETWORKING_IP_H_ */
