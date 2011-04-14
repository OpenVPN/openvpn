# This makefile builds the user-mode component
# of OpenVPN for Windows in the Visual Studio 2008 environment.

# To build:
#    python msvc\config.py
#    nmake /f msvc\msvc.mak

# Each of the OPENSSL and LZO dirs should have 'lib' and 'include'
# directories under them.

OPENSSL = \src\openssl
OPENSSL_DYNAMIC = libeay32.lib ssleay32.lib

LZO = \src\lzo
LZO_DYNAMIC = lzo2.lib

INCLUDE_DIRS = -I$(OPENSSL)/include -I$(LZO)/include

LIBS = $(OPENSSL_DYNAMIC) $(LZO_DYNAMIC) ws2_32.lib crypt32.lib iphlpapi.lib winmm.lib user32.lib gdi32.lib advapi32.lib wininet.lib

LIB_DIRS = -LIBPATH:$(OPENSSL)\lib -LIBPATH:$(LZO)\lib

EXE = openvpn.exe

CPP=cl.exe
CPP_ARG_COMMON=/nologo /W3 /O2 -DWIN32 -DWIN32_LEAN_AND_MEAN -D_CONSOLE -D_MBCS -D_CRT_SECURE_NO_DEPRECATE $(INCLUDE_DIRS) /FD /c
# release:
CPP_PROJ=$(CPP_ARG_COMMON) /MD -DNDEBUG
# debug:
#CPP_PROJ=$(CPP_ARG_COMMON) /MDd /Zi /Od -D_DEBUG

LINK32=link.exe
# release:
LINK32_FLAGS=/nologo /subsystem:console /incremental:no /out:"$(EXE)"
# debug:
#LINK32_FLAGS=/nologo /subsystem:console /incremental:no /debug /out:"$(EXE)"

# HEADERS and OBJS definitions, automatically generated
!INCLUDE head_obj.mak

openvpn : $(OBJS)
	$(LINK32) @<<
	$(LINK32_FLAGS) $(LIB_DIRS) $(LIBS) $(OBJS)
<<

clean :
	del /Q $(OBJS) $(EXE) *.idb *.pdb

.c.obj::
   $(CPP) @<<
   $(CPP_PROJ) $<
<<
