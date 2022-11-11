#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2002-2022 OpenVPN Inc <sales@openvpn.net>
#  Copyright (C) 2008-2012 Alon Bar-Lev <alon.barlev@gmail.com>
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

CONFIG=$(SOLUTIONDIR)/version.m4

INPUT_MSVC_VER=$(SOLUTIONDIR)/config-msvc-version.h.in
OUTPUT_MSVC_VER=$(SOLUTIONDIR)/config-msvc-version.h

INPUT_PLUGIN=$(SOLUTIONDIR)/include/openvpn-plugin.h.in
OUTPUT_PLUGIN=$(SOLUTIONDIR)/include/openvpn-plugin.h

INPUT_PLUGIN_CONFIG=version.m4.in
OUTPUT_PLUGIN_CONFIG=version.m4

INPUT_MAN=$(SOLUTIONDIR)/doc/openvpn.8.rst
OUTPUT_MAN=$(SOLUTIONDIR)/doc/openvpn.8.html

OUTPUT_MSVC_GIT_CONFIG=$(SOLUTIONDIR)/config-version.h

all:	$(OUTPUT_MSVC_VER) $(OUTPUT_PLUGIN) $(OUTPUT_MAN) $(OUTPUT_MSVC_GIT_CONFIG)

$(OUTPUT_MSVC_VER): $(INPUT_MSVC_VER) $(CONFIG)
	cscript //nologo msvc-generate.js --config="$(CONFIG)" --input="$(INPUT_MSVC_VER)" --output="$(OUTPUT_MSVC_VER)"

$(OUTPUT_PLUGIN_CONFIG): $(INPUT_PLUGIN_CONFIG)
	cscript //nologo msvc-generate.js --config="$(CONFIG)" --input="$(INPUT_PLUGIN_CONFIG)" --output="$(OUTPUT_PLUGIN_CONFIG)"

$(OUTPUT_PLUGIN): $(INPUT_PLUGIN) $(OUTPUT_PLUGIN_CONFIG)
	cscript //nologo msvc-generate.js --config="$(OUTPUT_PLUGIN_CONFIG)" --input="$(INPUT_PLUGIN)" --output="$(OUTPUT_PLUGIN)"

$(OUTPUT_MAN): $(INPUT_MAN)
	-FOR /F %i IN ('where rst2html.py') DO python %i "$(INPUT_MAN)" "$(OUTPUT_MAN)"

# Force regeneration because we can't detect whether it is outdated
$(OUTPUT_MSVC_GIT_CONFIG): FORCE
	python git-version.py $(SOLUTIONDIR)

FORCE:

clean:
	-del "$(OUTPUT_MSVC_VER)"
	-del "$(OUTPUT_PLUGIN)"
	-del "$(OUTPUT_PLUGIN_CONFIG)"
	-del "$(OUTPUT_MAN)"
	-del "$(OUTPUT_MSVC_GIT_CONFIG)"
