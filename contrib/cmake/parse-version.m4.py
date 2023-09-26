#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2022-2023 OpenVPN Inc <sales@openvpn.net>
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

# Usage: ./parse-version.m4.py m4file [directory]
# Read <m4file>, extract all lines looking like M4 define(), and translate
# them into CMake style set(). Those are then written out to file
# <directory>/version.cmake.
# Intended to be used on top-level version.m4 file.

import os
import re
import sys

def main():
    assert len(sys.argv) > 1
    version_path = sys.argv[1]
    output = []
    with open(version_path, 'r') as version_file:
        for line in version_file:
            match = re.match(r'[ \t]*define\(\[(.*)\],[ \t]*\[(.*)\]\)[ \t]*', line)
            if match is not None:
                output.append(match.expand(r'set(\1 \2)'))
    out_path = os.path.join("%s" %  (sys.argv[2] if len(sys.argv) > 2 else "."), "version.cmake")

    prev_content = ""
    try:
        with open(out_path, "r") as out_file:
            prev_content = out_file.read()
    except:
        # file doesn't exist
        pass

    content = "\n".join(output) + "\n"
    if prev_content != content:
        print("Writing %s" % out_path)
        with open(out_path, "w") as out_file:
            out_file.write(content)
    else:
        print("Content of %s hasn't changed" % out_path)

if __name__ == "__main__":
    main()

