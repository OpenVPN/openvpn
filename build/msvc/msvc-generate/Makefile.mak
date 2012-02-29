# Copyright (C) 2008-2012 Alon Bar-Lev <alon.barlev@gmail.com>

CONFIG=$(SOURCEBASE)/version.m4
INPUT=$(SOURCEBASE)/config-msvc-version.h.in
OUTPUT=$(SOURCEBASE)/config-msvc-version.h

all:	$(OUTPUT)

$(OUTPUT): $(INPUT) $(CONFIG)
	cscript //nologo msvc-generate.js --config="$(CONFIG)" --input="$(INPUT)" --output="$(OUTPUT)"

clean:
	-del "$(OUTPUT)"
