; ****************************************************************************
; * Copyright (C) 2002-2010 OpenVPN Technologies, Inc.                            *
; *  This program is free software; you can redistribute it and/or modify    *
; *  it under the terms of the GNU General Public License version 2          *
; *  as published by the Free Software Foundation.                           *
; ****************************************************************************

; OpenVPN install script for Windows, using NSIS

SetCompressor lzma

!include "MUI.nsh"

!include "defs.nsi"
!include "guidefs.nsi"
!include "xguidefs.nsi"
!include "setpath.nsi"
!include "GetWindowsVersion.nsi"

!ifdef EXTRACT_FILES
!include "MultiFileExtract.nsi"
!endif

!define GEN ".."
!define BIN "${GEN}\bin"
!define LIB "${GEN}\lib"

; Which GUI to use (XGUI has priority).
; We will define either USE_XGUI (XML-based version) or
; USE_GUI (Mathias Sundman version) but not both.
!ifdef OPENVPN_XGUI_DEFINED
!define USE_XGUI
!else
!ifdef OPENVPN_GUI_DEFINED
!define USE_GUI
!endif
!endif

!define PRODUCT_ICON "icon.ico"

!ifdef USE_XGUI
!define XGUI_POSTFIX "X"
!else
!define XGUI_POSTFIX ""
!endif

!ifdef PRODUCT_TAP_DEBUG
!define DBG_POSTFIX "-DBG"
!else
!define DBG_POSTFIX ""
!endif

!define VERSION "${PRODUCT_VERSION}${XGUI_POSTFIX}${DBG_POSTFIX}"

!define TAP "${PRODUCT_TAP_ID}"
!define TAPDRV "${TAP}.sys"

; Default service settings
!define SERV_CONFIG_DIR   "$INSTDIR\config"
!define SERV_CONFIG_EXT   "${PRODUCT_FILE_EXT}"
!define SERV_EXE_PATH     "$INSTDIR\bin\${PRODUCT_UNIX_NAME}.exe"
!define SERV_LOG_DIR      "$INSTDIR\log"
!define SERV_PRIORITY     "NORMAL_PRIORITY_CLASS"
!define SERV_LOG_APPEND   "0"

; XGUI variables
!define XGUI_EXE      ovpn-xgui-en.exe
!define XGUI_TRAY     ovpn-tray.exe
!define XGUI_XMLSERV  ovpn-xmlserv.exe
!define XGUI_HTDOCS   htdocs

!define XGUI_AJAX_GUI_NAME       "${PRODUCT_NAME} Ajax GUI"
!define XGUI_TRANSITION_GUI_NAME "${PRODUCT_NAME} Transitional GUI"

;--------------------------------
;Configuration

  ;General

  OutFile "${GEN}\${PRODUCT_UNIX_NAME}-${VERSION}${OUTFILE_LABEL}-install.exe"

  ShowInstDetails show
  ShowUninstDetails show

  ;Folder selection page
  InstallDir "$PROGRAMFILES\${PRODUCT_NAME}"
  
  ;Remember install folder
  InstallDirRegKey HKCU "Software\${PRODUCT_NAME}" ""

;--------------------------------
;Modern UI Configuration

  Name "${PRODUCT_NAME} ${VERSION} ${TITLE_LABEL}"

  !define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the installation of ${PRODUCT_NAME}, an Open Source VPN package by James Yonan.\r\n\r\nNote that the Windows version of ${PRODUCT_NAME} will only run on Win 2000, XP, or higher.\r\n\r\n\r\n"

  !define MUI_COMPONENTSPAGE_TEXT_TOP "Select the components to install/upgrade.  Stop any ${PRODUCT_NAME} processes or the ${PRODUCT_NAME} service if it is running.  All DLLs are installed locally."

  !define MUI_COMPONENTSPAGE_SMALLDESC
  !ifdef USE_XGUI
    !define MUI_FINISHPAGE_SHOWREADME "http://openvpn.net/"
    !define MUI_FINISHPAGE_SHOWREADME_NOTCHECKED
  !else
    !define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\INSTALL-win32.txt"
  !endif
  !define MUI_FINISHPAGE_NOAUTOCLOSE
  !define MUI_ABORTWARNING
  !define MUI_ICON "${GEN}\images\${PRODUCT_ICON}"
  !define MUI_UNICON "${GEN}\images\${PRODUCT_ICON}"
  !define MUI_HEADERIMAGE
  !define MUI_HEADERIMAGE_BITMAP "${GEN}\images\install-whirl.bmp"
  !define MUI_UNFINISHPAGE_NOAUTOCLOSE

  !insertmacro MUI_PAGE_WELCOME
  !insertmacro MUI_PAGE_LICENSE "${GEN}\text\license.txt"
  !insertmacro MUI_PAGE_COMPONENTS
  !insertmacro MUI_PAGE_DIRECTORY
  !insertmacro MUI_PAGE_INSTFILES
  !insertmacro MUI_PAGE_FINISH
  
  !insertmacro MUI_UNPAGE_CONFIRM
  !insertmacro MUI_UNPAGE_INSTFILES  
  !insertmacro MUI_UNPAGE_FINISH


;--------------------------------
;Languages
 
  !insertmacro MUI_LANGUAGE "English"
  
;--------------------------------
;Language Strings

  LangString DESC_SecOpenVPNUserSpace ${LANG_ENGLISH} "Install ${PRODUCT_NAME} user-space components, including ${PRODUCT_UNIX_NAME}.exe."

!ifdef USE_GUI
  LangString DESC_SecOpenVPNGUI ${LANG_ENGLISH} "Install ${PRODUCT_NAME} GUI by Mathias Sundman"
!endif

!ifdef USE_XGUI
  LangString DESC_SecOpenVPNXGUI ${LANG_ENGLISH} "Install ${PRODUCT_NAME} XML-based GUI"
!endif

  LangString DESC_SecOpenVPNEasyRSA ${LANG_ENGLISH} "Install ${PRODUCT_NAME} RSA scripts for X509 certificate management."

  LangString DESC_SecOpenSSLDLLs ${LANG_ENGLISH} "Install OpenSSL DLLs locally (may be omitted if DLLs are already installed globally)."

  LangString DESC_SecPKCS11DLLs ${LANG_ENGLISH} "Install PKCS#11 helper DLLs locally (may be omitted if DLLs are already installed globally)."

  LangString DESC_SecTAP ${LANG_ENGLISH} "Install/Upgrade the TAP virtual device driver.  Will not interfere with CIPE."

  LangString DESC_SecService ${LANG_ENGLISH} "Install the ${PRODUCT_NAME} service wrapper (${PRODUCT_UNIX_NAME}serv.exe)"

  LangString DESC_SecOpenSSLUtilities ${LANG_ENGLISH} "Install the OpenSSL Utilities (used for generating public/private key pairs)."

  LangString DESC_SecAddPath ${LANG_ENGLISH} "Add ${PRODUCT_NAME} executable directory to the current user's PATH."

  LangString DESC_SecAddShortcuts ${LANG_ENGLISH} "Add ${PRODUCT_NAME} shortcuts to the current user's Start Menu."

  LangString DESC_SecFileAssociation ${LANG_ENGLISH} "Register ${PRODUCT_NAME} config file association (*.${SERV_CONFIG_EXT})"

;--------------------------------
;Reserve Files
  
  ;Things that need to be extracted on first (keep these lines before any File command!)
  ;Only useful for BZIP2 compression
  
  ReserveFile "${GEN}\images\install-whirl.bmp"

;--------------------------------
;Macros

!macro WriteRegStringIfUndef ROOT SUBKEY KEY VALUE
Push $R0
ReadRegStr $R0 "${ROOT}" "${SUBKEY}" "${KEY}"
StrCmp $R0 "" +1 +2
WriteRegStr "${ROOT}" "${SUBKEY}" "${KEY}" '${VALUE}'
Pop $R0
!macroend

!macro DelRegStringIfUnchanged ROOT SUBKEY KEY VALUE
Push $R0
ReadRegStr $R0 "${ROOT}" "${SUBKEY}" "${KEY}"
StrCmp $R0 '${VALUE}' +1 +2
DeleteRegValue "${ROOT}" "${SUBKEY}" "${KEY}"
Pop $R0
!macroend

!macro DelRegKeyIfUnchanged ROOT SUBKEY VALUE
Push $R0
ReadRegStr $R0 "${ROOT}" "${SUBKEY}" ""
StrCmp $R0 '${VALUE}' +1 +2
DeleteRegKey "${ROOT}" "${SUBKEY}"
Pop $R0
!macroend

!macro DelRegKeyIfEmpty ROOT SUBKEY
Push $R0
EnumRegValue $R0 "${ROOT}" "${SUBKEY}" 1
StrCmp $R0 "" +1 +2
DeleteRegKey /ifempty "${ROOT}" "${SUBKEY}"
Pop $R0
!macroend

;------------------------------------------
;Set reboot flag based on tapinstall return

Function CheckReboot
  IntCmp $R0 1 "" noreboot noreboot
  IntOp $R0 0 & 0
  SetRebootFlag true
  DetailPrint "REBOOT flag set"
 noreboot:
FunctionEnd

;--------------------------------
;Installer Sections

Function .onInit
  ClearErrors

# Verify that user has admin privs
  UserInfo::GetName
  IfErrors ok
  Pop $R0
  UserInfo::GetAccountType
  Pop $R1
  StrCmp $R1 "Admin" ok
    Messagebox MB_OK "Administrator privileges required to install ${PRODUCT_NAME} [$R0/$R1]"
    Abort
  ok:

# Delete previous start menu
  RMDir /r $SMPROGRAMS\${PRODUCT_NAME}

!ifdef CHECK_WINDOWS_VERSION
# Check windows version
  Call GetWindowsVersion
  Pop $1
  StrCmp $1 "2000" goodwinver
  StrCmp $1 "XP" goodwinver
  StrCmp $1 "2003" goodwinver
  StrCmp $1 "VISTA" goodwinver

  Messagebox MB_OK "Sorry, ${PRODUCT_NAME} does not currently support Windows $1"
  Abort

goodwinver:
  System::Call "kernel32::GetCurrentProcess() i .s"
  System::Call "kernel32::IsWow64Process(i s, *i .r0)"
  IntCmp $0 0 init32bits

  ; we are running on 64-bit windows
  StrCmp $1 "VISTA" vista64bummer

#  Messagebox MB_OK "Sorry, ${PRODUCT_NAME} doesn't currently support 64-bit Windows."
#  Abort

vista64bummer:

#  Messagebox MB_OK "Sorry, ${PRODUCT_NAME} doesn't currently support 64-bit Vista because Microsoft doesn't allow the installation of 64 bit unsigned drivers."
#  Abort

init32bits:

!endif

FunctionEnd

!ifndef SF_SELECTED
!define SF_SELECTED 1
!endif

;--------------------
;Pre-install section

Section -pre

  ; Stop OpenVPN if currently running
  DetailPrint "Previous Service REMOVE (if exists)"
  nsExec::ExecToLog '"$INSTDIR\bin\${PRODUCT_UNIX_NAME}serv.exe" -remove'
  Pop $R0 # return value/error/timeout

!ifdef USE_XGUI
  DetailPrint "Previous XML Service REMOVE (if exists)"
  nsExec::ExecToLog '"$INSTDIR\bin\${XGUI_XMLSERV}" -remove'
  Pop $R0 # return value/error/timeout
!endif

  Sleep 3000

SectionEnd

Section "${PRODUCT_NAME} User-Space Components" SecOpenVPNUserSpace

  SetOverwrite on
  SetOutPath "$INSTDIR\bin"

  File "${BIN}\${PRODUCT_UNIX_NAME}.exe"

SectionEnd

!ifdef USE_GUI
Section "${PRODUCT_NAME} GUI" SecOpenVPNGUI

  SetOverwrite on
  SetOutPath "$INSTDIR\bin"

  File "${BIN}\${OPENVPN_GUI}"

SectionEnd
!endif

!ifdef USE_XGUI
Section "${PRODUCT_NAME} XML-based GUI" SecOpenVPNXGUI

  SetOverwrite on

  SetOutPath "$INSTDIR\bin"
  File "${BIN}\${XGUI_EXE}"
  File "${BIN}\${XGUI_TRAY}"
  File "${BIN}\${XGUI_XMLSERV}"

  SetOutPath "$INSTDIR\${XGUI_HTDOCS}"
  File "${GEN}\${XGUI_HTDOCS}\*.*"

SectionEnd
!endif

Section "${PRODUCT_NAME} RSA Certificate Management Scripts" SecOpenVPNEasyRSA

  SetOverwrite on
  SetOutPath "$INSTDIR\easy-rsa"

  File "${GEN}\easy-rsa\openssl-1.0.0.cnf"
  File "${GEN}\easy-rsa\vars.bat.sample"

  File "${GEN}\easy-rsa\init-config.bat"

  File "${GEN}\easy-rsa\README.txt"
  File "${GEN}\easy-rsa\build-ca.bat"
  File "${GEN}\easy-rsa\build-dh.bat"
  File "${GEN}\easy-rsa\build-key-server.bat"
  File "${GEN}\easy-rsa\build-key.bat"
  File "${GEN}\easy-rsa\build-key-pkcs12.bat"
  File "${GEN}\easy-rsa\clean-all.bat"
  File "${GEN}\easy-rsa\index.txt.start"
  File "${GEN}\easy-rsa\revoke-full.bat"
  File "${GEN}\easy-rsa\serial.start"

SectionEnd

Section "${PRODUCT_NAME} Service" SecService

  SetOverwrite on

  SetOutPath "$INSTDIR\bin"
  File "${BIN}\${PRODUCT_UNIX_NAME}serv.exe"

  SetOutPath "$INSTDIR\config"

  FileOpen $R0 "$INSTDIR\config\README.txt" w
  FileWrite $R0 "This directory should contain ${PRODUCT_NAME} configuration files$\r$\n"
  FileWrite $R0 "each having an extension of .${SERV_CONFIG_EXT}$\r$\n"
  FileWrite $R0 "$\r$\n"
  FileWrite $R0 "When ${PRODUCT_NAME} is started as a service, a separate ${PRODUCT_NAME}$\r$\n"
  FileWrite $R0 "process will be instantiated for each configuration file.$\r$\n"
  FileClose $R0

  SetOutPath "$INSTDIR\sample-config"
  File "${GEN}\samples\sample.${SERV_CONFIG_EXT}"
  File "${GEN}\samples\client.${SERV_CONFIG_EXT}"
  File "${GEN}\samples\server.${SERV_CONFIG_EXT}"

  CreateDirectory "$INSTDIR\log"
  FileOpen $R0 "$INSTDIR\log\README.txt" w
  FileWrite $R0 "This directory will contain the log files for ${PRODUCT_NAME}$\r$\n"
  FileWrite $R0 "sessions which are being run as a service.$\r$\n"
  FileClose $R0

SectionEnd

Section "${PRODUCT_NAME} File Associations" SecFileAssociation
SectionEnd

Section "OpenSSL DLLs" SecOpenSSLDLLs

  SetOverwrite on
  SetOutPath "$INSTDIR\bin"
  File "${LIB}\libeay32.dll"
  File "${LIB}\libssl32.dll"

SectionEnd

Section "OpenSSL Utilities" SecOpenSSLUtilities

  SetOverwrite on
  SetOutPath "$INSTDIR\bin"
  File "${BIN}\openssl.exe"

SectionEnd

Section "PKCS#11 DLLs" SecPKCS11DLLs

  SetOverwrite on
  SetOutPath "$INSTDIR\bin"
  File "${LIB}\libpkcs11-helper-1.dll"

SectionEnd

Section "TAP Virtual Ethernet Adapter" SecTAP

  SetOverwrite on

  FileOpen $R0 "$INSTDIR\bin\addtap.bat" w
  FileWrite $R0 "rem Add a new TAP virtual ethernet adapter$\r$\n"
  FileWrite $R0 '"$INSTDIR\bin\tapinstall.exe" install "$INSTDIR\driver\OemWin2k.inf" ${TAP}$\r$\n'
  FileWrite $R0 "pause$\r$\n"
  FileClose $R0

  FileOpen $R0 "$INSTDIR\bin\deltapall.bat" w
  FileWrite $R0 "echo WARNING: this script will delete ALL TAP virtual adapters (use the device manager to delete adapters one at a time)$\r$\n"
  FileWrite $R0 "pause$\r$\n"
  FileWrite $R0 '"$INSTDIR\bin\tapinstall.exe" remove ${TAP}$\r$\n'
  FileWrite $R0 "pause$\r$\n"
  FileClose $R0

  ; Check if we are running on a 64 bit system.
  System::Call "kernel32::GetCurrentProcess() i .s"
  System::Call "kernel32::IsWow64Process(i s, *i .r0)"
  IntCmp $0 0 tap-32bit

; tap-64bit:

  DetailPrint "We are running on a 64-bit system."

  SetOutPath "$INSTDIR\bin"

  File "${GEN}\tapinstall\amd64\tapinstall.exe"

  SetOutPath "$INSTDIR\driver"

  File "${GEN}\driver\amd64\OemWin2k.inf"
  File "${GEN}\driver\amd64\${PRODUCT_TAP_ID}.cat"
  File "${GEN}\driver\amd64\${TAPDRV}"

goto tapend

tap-32bit:

  DetailPrint "We are running on a 32-bit system."

  SetOutPath "$INSTDIR\bin"
  File "${GEN}\tapinstall\i386\tapinstall.exe"

  SetOutPath "$INSTDIR\driver"
  File "${GEN}\driver\i386\OemWin2k.inf"
  File "${GEN}\driver\i386\${PRODUCT_TAP_ID}.cat"
  File "${GEN}\driver\i386\${TAPDRV}"

  tapend:

SectionEnd

Section "Add ${PRODUCT_NAME} to PATH" SecAddPath

  ; remove previously set path (if any)
  Push "$INSTDIR\bin"
  Call RemoveFromPath

  ; append our bin directory to end of current user path
  Push "$INSTDIR\bin"
  Call AddToPath

SectionEnd

Section "Add Shortcuts to Start Menu" SecAddShortcuts

  SetOverwrite on
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}\Documentation"
  WriteINIStr "$SMPROGRAMS\${PRODUCT_NAME}\Documentation\${PRODUCT_NAME} Windows Notes.url" "InternetShortcut" "URL" "http://openvpn.net/INSTALL-win32.html"
  WriteINIStr "$SMPROGRAMS\${PRODUCT_NAME}\Documentation\${PRODUCT_NAME} Manual Page.url" "InternetShortcut" "URL" "http://openvpn.net/man.html"
  WriteINIStr "$SMPROGRAMS\${PRODUCT_NAME}\Documentation\${PRODUCT_NAME} HOWTO.url" "InternetShortcut" "URL" "http://openvpn.net/howto.html"
  WriteINIStr "$SMPROGRAMS\${PRODUCT_NAME}\Documentation\${PRODUCT_NAME} Web Site.url" "InternetShortcut" "URL" "http://openvpn.net/"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall ${PRODUCT_NAME}.lnk" "$INSTDIR\Uninstall.exe"

SectionEnd

;--------------------
;Post-install section

Section -post

  SetOverwrite on

  ; delete old devcon.exe
  Delete "$INSTDIR\bin\devcon.exe"

  ; Store README, license, icon
  SetOverwrite on
  SetOutPath $INSTDIR
  !ifndef USE_XGUI
    File "${GEN}\text\INSTALL-win32.txt"
  !endif
  File "${GEN}\text\license.txt"
  File "${GEN}\images\${PRODUCT_ICON}"

  ; store sample config files
  !ifdef SAMPCONF_DIR
    SetOverwrite on
    SetOutPath "$INSTDIR\config"
  !ifdef SAMPCONF_CONF
    File "${GEN}\conf\${SAMPCONF_CONF}"
  !endif
  !ifdef SAMPCONF_CONF2
    File "${GEN}\conf\${SAMPCONF_CONF2}"
  !endif
  !ifdef SAMPCONF_P12
    File "${GEN}\conf\${SAMPCONF_P12}"
  !endif
  !ifdef SAMPCONF_TA
    File "${GEN}\conf\${SAMPCONF_TA}"
  !endif
  !ifdef SAMPCONF_CA
    File "${GEN}\conf\${SAMPCONF_CA}"
  !endif
  !ifdef SAMPCONF_CRT
    File "${GEN}\conf\${SAMPCONF_CRT}"
  !endif
  !ifdef SAMPCONF_KEY
    File "${GEN}\conf\${SAMPCONF_KEY}"
  !endif
  !ifdef SAMPCONF_DH
    File "${GEN}\conf\${SAMPCONF_DH}"
  !endif
  !endif

  ; Try to extract files if present
  !ifdef EXTRACT_FILES
    Push "$INSTDIR"
    Call MultiFileExtract
    Pop $R0
    IntCmp $R0 0 +3 +1 +1
    DetailPrint "MultiFileExtract Failed status=$R0"
    goto +2
    DetailPrint "MultiFileExtract Succeeded"
  !endif

  ;
  ; install/upgrade TAP driver if selected, using tapinstall.exe
  ;
  SectionGetFlags ${SecTAP} $R0
  IntOp $R0 $R0 & ${SF_SELECTED}
  IntCmp $R0 ${SF_SELECTED} "" notap notap
    ; TAP install/update was selected.
    ; Should we install or update?
    ; If tapinstall error occurred, $5 will
    ; be nonzero.
    IntOp $5 0 & 0
    nsExec::ExecToStack '"$INSTDIR\bin\tapinstall.exe" hwids ${TAP}'
    Pop $R0 # return value/error/timeout
    IntOp $5 $5 | $R0
    DetailPrint "tapinstall hwids returned: $R0"

    ; If tapinstall output string contains "${TAP}" we assume
    ; that TAP device has been previously installed,
    ; therefore we will update, not install.
    Push "${TAP}"
    Call StrStr
    Pop $R0

    IntCmp $5 0 "" tapinstall_check_error tapinstall_check_error
    IntCmp $R0 -1 tapinstall

 ;tapupdate:
    DetailPrint "TAP UPDATE"
    nsExec::ExecToLog '"$INSTDIR\bin\tapinstall.exe" update "$INSTDIR\driver\OemWin2k.inf" ${TAP}'
    Pop $R0 # return value/error/timeout
    Call CheckReboot
    IntOp $5 $5 | $R0
    DetailPrint "tapinstall update returned: $R0"
    Goto tapinstall_check_error

 tapinstall:
    DetailPrint "TAP REMOVE OLD TAP"

    nsExec::ExecToLog '"$INSTDIR\bin\tapinstall.exe" remove TAP0801'
    Pop $R0 # return value/error/timeout
    DetailPrint "tapinstall remove TAP0801 returned: $R0"

    DetailPrint "TAP INSTALL (${TAP})"
    nsExec::ExecToLog '"$INSTDIR\bin\tapinstall.exe" install "$INSTDIR\driver\OemWin2k.inf" ${TAP}'
    Pop $R0 # return value/error/timeout
    Call CheckReboot
    IntOp $5 $5 | $R0
    DetailPrint "tapinstall install returned: $R0"

 tapinstall_check_error:
    DetailPrint "tapinstall cumulative status: $5"
    IntCmp $5 0 notap
    MessageBox MB_OK "An error occurred installing the TAP device driver."

 notap:

  ; Store install folder in registry
  WriteRegStr HKLM SOFTWARE\${PRODUCT_NAME} "" $INSTDIR

  ; install as a service if requested
  SectionGetFlags ${SecService} $R0
  IntOp $R0 $R0 & ${SF_SELECTED}
  IntCmp $R0 ${SF_SELECTED} "" noserv noserv

    ; set registry parameters for openvpnserv	
    !insertmacro WriteRegStringIfUndef HKLM "SOFTWARE\${PRODUCT_NAME}" "config_dir"  "${SERV_CONFIG_DIR}"
    !insertmacro WriteRegStringIfUndef HKLM "SOFTWARE\${PRODUCT_NAME}" "config_ext"  "${SERV_CONFIG_EXT}"
    !insertmacro WriteRegStringIfUndef HKLM "SOFTWARE\${PRODUCT_NAME}" "exe_path"    "${SERV_EXE_PATH}"
    !insertmacro WriteRegStringIfUndef HKLM "SOFTWARE\${PRODUCT_NAME}" "log_dir"     "${SERV_LOG_DIR}"
    !insertmacro WriteRegStringIfUndef HKLM "SOFTWARE\${PRODUCT_NAME}" "priority"    "${SERV_PRIORITY}"
    !insertmacro WriteRegStringIfUndef HKLM "SOFTWARE\${PRODUCT_NAME}" "log_append"  "${SERV_LOG_APPEND}"

    ; install openvpnserv as a service (to be started manually from service control manager)
    DetailPrint "Service INSTALL"
    nsExec::ExecToLog '"$INSTDIR\bin\${PRODUCT_UNIX_NAME}serv.exe" -install'
    Pop $R0 # return value/error/timeout

 noserv:
  !ifdef USE_XGUI
    IfFileExists "$INSTDIR\bin\${XGUI_XMLSERV}" "" fileass
      ; install and automatically start XML service
      DetailPrint "XML Service INSTALL"
      nsExec::ExecToLog '"$INSTDIR\bin\${XGUI_XMLSERV}" -install'
      Pop $R0 # return value/error/timeout

      Sleep 2000

      DetailPrint "XML Service START"
      nsExec::ExecToLog '"$INSTDIR\bin\${XGUI_XMLSERV}" -start'
      Pop $R0 # return value/error/timeout

  !endif

  ; Create file association if requested
 fileass:
  SectionGetFlags ${SecFileAssociation} $R0
  IntOp $R0 $R0 & ${SF_SELECTED}
  IntCmp $R0 ${SF_SELECTED} "" noass noass
    WriteRegStr HKCR ".${SERV_CONFIG_EXT}" "" "${PRODUCT_NAME}File"
    WriteRegStr HKCR "${PRODUCT_NAME}File" "" "${PRODUCT_NAME} Config File"
    WriteRegStr HKCR "${PRODUCT_NAME}File\shell" "" "open"
    WriteRegStr HKCR "${PRODUCT_NAME}File\DefaultIcon" "" "$INSTDIR\${PRODUCT_ICON},0"
    WriteRegStr HKCR "${PRODUCT_NAME}File\shell\open\command" "" 'notepad.exe "%1"'
    WriteRegStr HKCR "${PRODUCT_NAME}File\shell\run" "" "Start ${PRODUCT_NAME} on this config file"
    WriteRegStr HKCR "${PRODUCT_NAME}File\shell\run\command" "" '"$INSTDIR\bin\${PRODUCT_UNIX_NAME}.exe" --pause-exit --config "%1"'

  ; Create start menu folders
 noass:
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}\Utilities"
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}\Shortcuts"

  ; Create start menu and desktop shortcuts to OpenVPN GUI
  !ifdef USE_GUI
    IfFileExists "$INSTDIR\bin\${OPENVPN_GUI}" "" tryaddxgui
      CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME} GUI.lnk" "$INSTDIR\bin\${OPENVPN_GUI}" ""
      CreateShortcut "$DESKTOP\${PRODUCT_NAME} GUI.lnk" "$INSTDIR\bin\${OPENVPN_GUI}"
  !endif

  ; Create start menu and desktop shortcuts to OpenVPN XGUI
 tryaddxgui:
  !ifdef USE_XGUI
    IfFileExists "$INSTDIR\bin\${XGUI_EXE}" "" tryaddtray
      CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\${XGUI_TRANSITION_GUI_NAME}.lnk" "$INSTDIR\bin\${XGUI_EXE}" ""
#      CreateShortcut "$DESKTOP\${XGUI_TRANSITION_GUI_NAME}.lnk" "$INSTDIR\bin\${XGUI_EXE}"
 tryaddtray:
    IfFileExists "$INSTDIR\bin\${XGUI_TRAY}" "" tryaddtap
      CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\${XGUI_AJAX_GUI_NAME}.lnk" "$INSTDIR\bin\${XGUI_EXE}" ""
      CreateShortcut "$DESKTOP\${XGUI_AJAX_GUI_NAME}.lnk" "$INSTDIR\bin\${XGUI_TRAY}"
  !endif

    ; Create start menu shortcuts to addtap.bat and deltapall.bat
 tryaddtap:
    IfFileExists "$INSTDIR\bin\addtap.bat" "" trydeltap
      CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Utilities\Add a new TAP virtual ethernet adapter.lnk" "$INSTDIR\bin\addtap.bat" ""

 trydeltap:
    IfFileExists "$INSTDIR\bin\deltapall.bat" "" config_shortcut
      CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Utilities\Delete ALL TAP virtual ethernet adapters.lnk" "$INSTDIR\bin\deltapall.bat" ""

    ; Create start menu shortcuts for config and log directories
 config_shortcut:
    IfFileExists "$INSTDIR\config" "" log_shortcut
      CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Shortcuts\${PRODUCT_NAME} configuration file directory.lnk" "$INSTDIR\config" ""

 log_shortcut:
    IfFileExists "$INSTDIR\log" "" samp_shortcut
      CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Shortcuts\${PRODUCT_NAME} log file directory.lnk" "$INSTDIR\log" ""

 samp_shortcut:
    IfFileExists "$INSTDIR\sample-config" "" genkey_shortcut
      CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Shortcuts\${PRODUCT_NAME} Sample Configuration Files.lnk" "$INSTDIR\sample-config" ""

 genkey_shortcut:
    IfFileExists "$INSTDIR\bin\${PRODUCT_UNIX_NAME}.exe" "" noshortcuts
      IfFileExists "$INSTDIR\config" "" noshortcuts
        CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Utilities\Generate a static ${PRODUCT_NAME} key.lnk" "$INSTDIR\bin\${PRODUCT_UNIX_NAME}.exe" '--pause-exit --verb 3 --genkey --secret "$INSTDIR\config\key.txt"' "$INSTDIR\${PRODUCT_ICON}" 0

 noshortcuts:
  ; Create uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  ; Show up in Add/Remove programs
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "DisplayName" "${PRODUCT_NAME} ${VERSION}"
  WriteRegExpandStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "UninstallString" "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "DisplayIcon" "$INSTDIR\${PRODUCT_ICON}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "DisplayVersion" "${VERSION}"

  ; Advise a reboot
  ;Messagebox MB_OK "IMPORTANT: Rebooting the system is advised in order to finalize TAP driver installation/upgrade (this is an informational message only, pressing OK will not reboot)."

SectionEnd

;--------------------------------
;Descriptions

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecOpenVPNUserSpace} $(DESC_SecOpenVPNUserSpace)
  !ifdef USE_GUI
    !insertmacro MUI_DESCRIPTION_TEXT ${SecOpenVPNGUI} $(DESC_SecOpenVPNGUI)
  !endif
  !ifdef USE_XGUI
    !insertmacro MUI_DESCRIPTION_TEXT ${SecOpenVPNXGUI} $(DESC_SecOpenVPNXGUI)
  !endif
  !insertmacro MUI_DESCRIPTION_TEXT ${SecOpenVPNEasyRSA} $(DESC_SecOpenVPNEasyRSA)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecTAP} $(DESC_SecTAP)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecOpenSSLUtilities} $(DESC_SecOpenSSLUtilities)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecOpenSSLDLLs} $(DESC_SecOpenSSLDLLs)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecPKCS11DLLs} $(DESC_SecPKCS11DLLs)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecAddPath} $(DESC_SecAddPath)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecAddShortcuts} $(DESC_SecAddShortcuts)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecService} $(DESC_SecService)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecFileAssociation} $(DESC_SecFileAssociation)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

;--------------------------------
;Uninstaller Section

Function un.onInit
  ClearErrors
  UserInfo::GetName
  IfErrors ok
  Pop $R0
  UserInfo::GetAccountType
  Pop $R1
  StrCmp $R1 "Admin" ok
    Messagebox MB_OK "Administrator privileges required to uninstall ${PRODUCT_NAME} [$R0/$R1]"
    Abort
  ok:
FunctionEnd

Section "Uninstall"

!ifdef USE_XGUI
  DetailPrint "XML Service REMOVE"
  nsExec::ExecToLog '"$INSTDIR\bin\${XGUI_XMLSERV}" -remove'
  Pop $R0 # return value/error/timeout
!endif

  ; Stop OpenVPN if currently running
  DetailPrint "Service REMOVE"
  nsExec::ExecToLog '"$INSTDIR\bin\${PRODUCT_UNIX_NAME}serv.exe" -remove'
  Pop $R0 # return value/error/timeout

  Sleep 3000

  DetailPrint "TAP REMOVE"
  nsExec::ExecToLog '"$INSTDIR\bin\tapinstall.exe" remove ${TAP}'
  Pop $R0 # return value/error/timeout
  DetailPrint "tapinstall remove returned: $R0"

  Push "$INSTDIR\bin"
  Call un.RemoveFromPath

  RMDir /r $SMPROGRAMS\${PRODUCT_NAME}

  ; delete sample config files
  !ifdef SAMPCONF_DIR
  !ifdef SAMPCONF_CONF
    Delete "$INSTDIR\config\${SAMPCONF_CONF}"
  !endif
  !ifdef SAMPCONF_CONF2
    Delete "$INSTDIR\config\${SAMPCONF_CONF2}"
  !endif
  !ifdef SAMPCONF_P12
    Delete "$INSTDIR\config\${SAMPCONF_P12}"
  !endif
  !ifdef SAMPCONF_TA
    Delete "$INSTDIR\config\${SAMPCONF_TA}"
  !endif
  !ifdef SAMPCONF_CA
    Delete "$INSTDIR\config\${SAMPCONF_CA}"
  !endif
  !ifdef SAMPCONF_CRT
    Delete "$INSTDIR\config\${SAMPCONF_CRT}"
  !endif
  !ifdef SAMPCONF_KEY
    Delete "$INSTDIR\config\${SAMPCONF_KEY}"
  !endif
  !ifdef SAMPCONF_DH
    Delete "$INSTDIR\config\${SAMPCONF_DH}"
  !endif
  !endif

  !ifdef USE_GUI
    Delete "$INSTDIR\bin\${OPENVPN_GUI}"
    Delete "$DESKTOP\${PRODUCT_NAME} GUI.lnk"
  !endif

  !ifdef USE_XGUI
    Delete "$INSTDIR\bin\${XGUI_EXE}"
    Delete "$INSTDIR\bin\${XGUI_TRAY}"
    Delete "$INSTDIR\bin\${XGUI_XMLSERV}"
    RMDir /r "$INSTDIR\${XGUI_HTDOCS}"
    Delete "$DESKTOP\${XGUI_AJAX_GUI_NAME}.lnk"
    Delete "$DESKTOP\${XGUI_TRANSITION_GUI_NAME}.lnk"
  !endif

  Delete "$INSTDIR\bin\${PRODUCT_UNIX_NAME}.exe"
  Delete "$INSTDIR\bin\${PRODUCT_UNIX_NAME}serv.exe"
  Delete "$INSTDIR\bin\libeay32.dll"
  Delete "$INSTDIR\bin\libssl32.dll"
  Delete "$INSTDIR\bin\libpkcs11-helper-1.dll"
  Delete "$INSTDIR\bin\tapinstall.exe"
  Delete "$INSTDIR\bin\addtap.bat"
  Delete "$INSTDIR\bin\deltapall.bat"

  Delete "$INSTDIR\config\README.txt"
  Delete "$INSTDIR\config\sample.${SERV_CONFIG_EXT}.txt"

  Delete "$INSTDIR\log\README.txt"

  Delete "$INSTDIR\driver\OemWin2k.inf"
  Delete "$INSTDIR\driver\${PRODUCT_TAP_ID}.cat"
  Delete "$INSTDIR\driver\${TAPDRV}"

  Delete "$INSTDIR\bin\openssl.exe"

  Delete "$INSTDIR\INSTALL-win32.txt"
  Delete "$INSTDIR\${PRODUCT_ICON}"
  Delete "$INSTDIR\license.txt"
  Delete "$INSTDIR\Uninstall.exe"

  Delete "$INSTDIR\easy-rsa\openssl-1.0.0.cnf"
  Delete "$INSTDIR\easy-rsa\vars.bat.sample"
  Delete "$INSTDIR\easy-rsa\init-config.bat"
  Delete "$INSTDIR\easy-rsa\README.txt"
  Delete "$INSTDIR\easy-rsa\build-ca.bat"
  Delete "$INSTDIR\easy-rsa\build-dh.bat"
  Delete "$INSTDIR\easy-rsa\build-key-server.bat"
  Delete "$INSTDIR\easy-rsa\build-key.bat"
  Delete "$INSTDIR\easy-rsa\build-key-pkcs12.bat"
  Delete "$INSTDIR\easy-rsa\clean-all.bat"
  Delete "$INSTDIR\easy-rsa\index.txt.start"
  Delete "$INSTDIR\easy-rsa\revoke-key.bat"
  Delete "$INSTDIR\easy-rsa\revoke-full.bat"
  Delete "$INSTDIR\easy-rsa\serial.start"

  Delete "$INSTDIR\sample-config\*.${PRODUCT_FILE_EXT}"

  RMDir "$INSTDIR\bin"
  RMDir "$INSTDIR\config"
  RMDir "$INSTDIR\driver"
  RMDir "$INSTDIR\easy-rsa"
  RMDir "$INSTDIR\sample-config"
  RMDir /r "$INSTDIR\log"
  RMDir "$INSTDIR"

  !insertmacro DelRegKeyIfUnchanged HKCR ".${SERV_CONFIG_EXT}" "${PRODUCT_NAME}File"
  DeleteRegKey HKCR "${PRODUCT_NAME}File"
  DeleteRegKey HKLM SOFTWARE\${PRODUCT_NAME}
  DeleteRegKey HKCU "Software\${PRODUCT_NAME}"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"

  ;Messagebox MB_OK "IMPORTANT: If you intend on reinstalling ${PRODUCT_NAME} after this uninstall, and you are running Win2K, you are strongly urged to reboot before reinstalling (this is an informational message only, pressing OK will not reboot)."

SectionEnd
