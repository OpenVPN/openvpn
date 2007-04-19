# Version numbers, settings, and dependencies
# for Windows OpenVPN installer.

!define PRODUCT_VERSION "2.1_rc2e"

# For now, use prebuilt AMD64 tap/tapinstall
#!define TAP_BIN_AMD64 "../amd64/tap/tap0901.sys"
#!define TI_BIN_AMD64  "../amd64/tapinstall/tapinstall.exe"

# Prebuilt libraries.  DMALLOC is optional.
!define OPENSSL_DIR	"../openssl-0.9.7l"
!define LZO_DIR		"../lzo-2.02"
!define DMALLOC_DIR	"../dmalloc-5.4.2"

# Write TAP driver and tapinstall.exe to this directory,
# to use as prebuilt binaries for future builds.  May
# be undefined.
;!define DRVBINDEST "../tapbin"

# Don't build TAP driver and tapinstall.exe -- instead get
# them as prebuilt binaries from this directory.  May be
# undefined.
;!define DRVBINSRC  "../tapbin"

# tapinstall.exe source code.
# Not needed if DRVBINSRC is defined.
!define TISRC	"../tapinstall"

# TAP Adapter parameters.
!define PRODUCT_TAP_MAJOR_VER       9
!define PRODUCT_TAP_MINOR_VER       3
!define PRODUCT_TAP_RELDATE         "04/18/2007"

# Service template files service.[ch] (get from Platform SDK).
# If undefined, don't build openvpnserv.exe
!define SVC_TEMPLATE "../svc-template"

# DDK Version.
# DDK distribution is assumed to be in C:\WINDDK\${DDKVER}
# Not needed if DRVBINSRC is defined.
!define DDKVER	5600

# Code Signing.
# This directory should contain signcode.exe + key files.
# If undefined, don't sign any files.
!define SIGNCODE "../sign"

# INF2CAT should point to the MS inf2cat distribution.
# inf2cat is used for driver signing.
# If undefined, don't sign any files.
!define INF2CAT	"../inf2cat"

# -j parameter passed to make
!define MAKE_JOBS 2

# do a make clean before make
!define MAKE_CLEAN "yes"
