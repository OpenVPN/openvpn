# This makefile builds the OpenVPN service wrapper for Windows in the 
# Visual Studio 2008 environment.

# Some of these libs may not be needed
LIBS = ws2_32.lib crypt32.lib iphlpapi.lib winmm.lib user32.lib gdi32.lib advapi32.lib wininet.lib
EXE = openvpnserv.exe

CPP=cl.exe
CPP_ARG_COMMON=/nologo /W3 -DWIN32 -DWIN32_LEAN_AND_MEAN -D_CONSOLE -D_MBCS -D_CRT_SECURE_NO_DEPRECATE /FD /c -I".."
CPP_PROJ=$(CPP_ARG_COMMON) /O2 /MD -DNDEBUG

LINK32=link.exe
LINK32_FLAGS=/nologo /subsystem:console /incremental:no

OBJS = \
	openvpnserv.obj \
	service.obj

openvpnserv : $(OBJS)
	$(LINK32) @<<
	$(LINK32_FLAGS) "/out:$(EXE)" $(LIBS) $(OBJS)
<<

clean :
	del /Q $(OBJS) $(EXE) *.idb *.pdb

.c.obj::
   $(CPP) @<<
   $(CPP_PROJ) $<
<<
