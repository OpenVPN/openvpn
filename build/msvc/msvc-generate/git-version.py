#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2022-2022 OpenVPN Inc <sales@openvpn.net>
#  Copyright (C) 2022-2022 Lev Stipakov <lev@lestisoftware.fi>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License version 2
#  as published by the Free Software Foundation.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License along
#  with this program; if not, write to the Free Software Foundation, Inc.,
#  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

import os
import sys

def get_branch_commit_id():
    commit_id = os.popen("git rev-parse --short=16 HEAD").read()[:-1]
    if not commit_id:
        raise
    l = os.popen("git rev-parse --symbolic-full-name HEAD").read().split("/")[2:]
    if not l:
        l = ["none\n"]
    branch = "/" .join(l)[:-1]
    return branch, commit_id

def main():
    try:
        branch, commit_id = get_branch_commit_id()
    except:
        branch, commit_id = "unknown", "unknown"

    name = os.path.join("%s" %  (sys.argv[1] if len(sys.argv) > 1 else "."), "config-version.h")
    with open(name, "w") as f:
        f.write("#define CONFIGURE_GIT_REVISION \"%s/%s\"\n" % (branch, commit_id))
        f.write("#define CONFIGURE_GIT_FLAGS \"\"\n")

if __name__ == "__main__":
    main()
