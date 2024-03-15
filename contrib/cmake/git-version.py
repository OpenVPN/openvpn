#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2022-2024 OpenVPN Inc <sales@openvpn.net>
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

# Usage: ./git-version.py [directory]
# Find a good textual representation of the git commit currently checked out.
# Make that representation available as CONFIGURE_GIT_REVISION in
# <directory>/config-version.h.
# It will prefer a tag name if it is checked out exactly, otherwise will use
# the branch name. 'none' if no branch is checked out (detached HEAD).
# This is used to enhance the output of openvpn --version with Git information.

import os
import sys
import subprocess

def run_command(args):
    sp = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    o, _ = sp.communicate()
    return o.decode("utf-8")[:-1]

def get_branch_commit_id():
    commit_id = run_command(["git", "rev-parse", "--short=16", "HEAD"])
    if not commit_id:
        raise
    branch = run_command(["git", "describe", "--exact-match"])
    if not branch:
        # this returns an array like ["master"] or ["release", "2.6"]
        branch = run_command(["git", "rev-parse", "--symbolic-full-name", "HEAD"]).split("/")[2:]
        if not branch:
            branch = ["none"]
        branch = "/" .join(branch) # handle cases like release/2.6

    return branch, commit_id

def main():
    try:
        branch, commit_id = get_branch_commit_id()
    except:
        branch, commit_id = "unknown", "unknown"

    prev_content = ""

    name = os.path.join("%s" %  (sys.argv[1] if len(sys.argv) > 1 else "."), "config-version.h")
    try:
        with open(name, "r") as f:
            prev_content = f.read()
    except:
        # file doesn't exist
        pass

    content = "#define CONFIGURE_GIT_REVISION \"%s/%s\"\n" % (branch, commit_id)
    content += "#define CONFIGURE_GIT_FLAGS \"\"\n"

    if prev_content != content:
        print("Writing %s" % name)
        with open(name, "w") as f:
            f.write(content)
    else:
        print("Content of %s hasn't changed" % name)

if __name__ == "__main__":
    main()
