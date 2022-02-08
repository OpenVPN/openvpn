# Copyright (C) 2008-2012 Alon Bar-Lev <alon.barlev@gmail.com>

CONFIG=$(SOLUTIONDIR)/version.m4

INPUT_MSVC_VER=$(SOLUTIONDIR)/config-msvc-version.h.in
OUTPUT_MSVC_VER=$(SOLUTIONDIR)/config-msvc-version.h

INPUT_PLUGIN=$(SOLUTIONDIR)/include/openvpn-plugin.h.in
OUTPUT_PLUGIN=$(SOLUTIONDIR)/include/openvpn-plugin.h

INPUT_PLUGIN_CONFIG=version.m4.in
OUTPUT_PLUGIN_CONFIG=version.m4

INPUT_MAN=$(SOLUTIONDIR)/doc/openvpn.8.rst
OUTPUT_MAN=$(SOLUTIONDIR)/doc/openvpn.8.html

all:	$(OUTPUT_MSVC_VER) $(OUTPUT_PLUGIN) $(OUTPUT_MAN)

$(OUTPUT_MSVC_VER): $(INPUT_MSVC_VER) $(CONFIG)
	cscript //nologo msvc-generate.js --config="$(CONFIG)" --input="$(INPUT_MSVC_VER)" --output="$(OUTPUT_MSVC_VER)"

$(OUTPUT_PLUGIN_CONFIG): $(INPUT_PLUGIN_CONFIG)
	cscript //nologo msvc-generate.js --config="$(CONFIG)" --input="$(INPUT_PLUGIN_CONFIG)" --output="$(OUTPUT_PLUGIN_CONFIG)"

$(OUTPUT_PLUGIN): $(INPUT_PLUGIN) $(OUTPUT_PLUGIN_CONFIG)
	cscript //nologo msvc-generate.js --config="$(OUTPUT_PLUGIN_CONFIG)" --input="$(INPUT_PLUGIN)" --output="$(OUTPUT_PLUGIN)"

$(OUTPUT_MAN): $(INPUT_MAN)
    -FOR /F %i IN ('where rst2html.py') DO python %i "$(INPUT_MAN)" "$(OUTPUT_MAN)"

clean:
	-del "$(OUTPUT_MSVC_VER)"
	-del "$(OUTPUT_PLUGIN)"
	-del "$(OUTPUT_PLUGIN_CONFIG)"
	-del "$(OUTPUT_MAN)"
