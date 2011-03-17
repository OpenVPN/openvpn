; Modify the user's PATH variable.
;
; Modified by JY to have both a RemoveFromPath
; and an un.RemoveFromPath which are basically
; copies of each other.  Why does NSIS demand
; this nonsense?
;
; Modified Feb 14, 2005 by Mathias Sundman:
;   Added code to remove the semicolon at the end of the path
;   when uninstalling.
;
;   Added code to make sure we don't insert an extra semicolon
;   before our path if there already exist one at the end of
;   the original path.
;
;   Removed duplicated "un. and install" functions and made
;   macros to duplicate the code instead.

; example usage
;
;Section "Add to path"
;  Push $INSTDIR
;  Call AddToPath
;SectionEnd
;
;# ...
;
;Section "uninstall"
;  # ...
;  Push $INSTDIR
;  Call un.RemoveFromPath
;  # ...
;SectionEnd

!verbose 3
!include "WinMessages.NSH"
!verbose 4

;====================================================
; AddToPath - Adds the given dir to the search path.
;        Input - head of the stack
;        Note - Win9x systems requires reboot
;====================================================
Function AddToPath
  Exch $0
  Push $1
  Push $2
  
  Call IsNT
  Pop $1
  StrCmp $1 1 AddToPath_NT
    ; Not on NT
    StrCpy $1 $WINDIR 2
    FileOpen $1 "$1\autoexec.bat" a
    FileSeek $1 0 END
    GetFullPathName /SHORT $0 $0
    FileWrite $1 "$\r$\nSET PATH=%PATH%;$0$\r$\n"
    FileClose $1
    Goto AddToPath_done

  AddToPath_NT:
    ReadRegStr $1 HKCU "Environment" "PATH"
    StrCpy $2 $1 1 -1 # copy last char
    StrCmp $2 ";" 0 +2 # if last char == ;
      StrCpy $1 $1 -1 # remove last char

    StrCmp $1 "" AddToPath_NTdoIt
      StrCpy $0 "$1;$0"
      Goto AddToPath_NTdoIt
    AddToPath_NTdoIt:
      WriteRegExpandStr HKCU "Environment" "PATH" $0
      SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
  
  AddToPath_done:
    Pop $2
    Pop $1
    Pop $0
FunctionEnd

;====================================================
; RemoveFromPath - Remove a given dir from the path
;     Input: head of the stack
;====================================================
!macro RemoveFromPath un
Function ${un}RemoveFromPath
  Exch $0
  Push $1
  Push $2
  Push $3
  Push $4
  Push $5
  
  Call ${un}IsNT
  Pop $1
  StrCmp $1 1 RemoveFromPath_NT
    ; Not on NT
    StrCpy $1 $WINDIR 2
    FileOpen $1 "$1\autoexec.bat" r
    GetTempFileName $4
    FileOpen $2 $4 w
    GetFullPathName /SHORT $0 $0
    StrCpy $0 "SET PATH=%PATH%;$0"
    SetRebootFlag true
    Goto RemoveFromPath_dosLoop
    
    RemoveFromPath_dosLoop:
      FileRead $1 $3
      StrCmp $3 "$0$\r$\n" RemoveFromPath_dosLoop
      StrCmp $3 "$0$\n" RemoveFromPath_dosLoop
      StrCmp $3 "$0" RemoveFromPath_dosLoop
      StrCmp $3 "" RemoveFromPath_dosLoopEnd
      FileWrite $2 $3
      Goto RemoveFromPath_dosLoop
    
    RemoveFromPath_dosLoopEnd:
      FileClose $2
      FileClose $1
      StrCpy $1 $WINDIR 2
      Delete "$1\autoexec.bat"
      CopyFiles /SILENT $4 "$1\autoexec.bat"
      Delete $4
      Goto RemoveFromPath_done

  RemoveFromPath_NT:
    StrLen $2 $0
    ReadRegStr $1 HKCU "Environment" "PATH"
    Push $1
    Push $0
    Call ${un}StrStr ; Find $0 in $1
    Pop $0 ; pos of our dir
    IntCmp $0 -1 RemoveFromPath_done
      ; else, it is in path
      StrCpy $3 $1 $0 ; $3 now has the part of the path before our dir
      IntOp $2 $2 + $0 ; $2 now contains the pos after our dir in the path (';')
      IntOp $2 $2 + 1 ; $2 now containts the pos after our dir and the semicolon.
      StrLen $0 $1
      StrCpy $1 $1 $0 $2
      StrCpy $3 "$3$1"

      StrCpy $5 $3 1 -1 # copy last char
      StrCmp $5 ";" 0 +2 # if last char == ;
        StrCpy $3 $3 -1 # remove last char

      WriteRegExpandStr HKCU "Environment" "PATH" $3
      SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
  
  RemoveFromPath_done:
    Pop $5
    Pop $4
    Pop $3
    Pop $2
    Pop $1
    Pop $0
FunctionEnd
!macroend
!insertmacro RemoveFromPath ""
!insertmacro RemoveFromPath "un."


;====================================================
; StrStr - Finds a given string in another given string.
;               Returns -1 if not found and the pos if found.
;          Input: head of the stack - string to find
;                      second in the stack - string to find in
;          Output: head of the stack
;====================================================
!macro StrStr un
Function ${un}StrStr
  Push $0
  Exch
  Pop $0 ; $0 now have the string to find
  Push $1
  Exch 2
  Pop $1 ; $1 now have the string to find in
  Exch
  Push $2
  Push $3
  Push $4
  Push $5

  StrCpy $2 -1
  StrLen $3 $0
  StrLen $4 $1
  IntOp $4 $4 - $3

  StrStr_loop:
    IntOp $2 $2 + 1
    IntCmp $2 $4 0 0 StrStrReturn_notFound
    StrCpy $5 $1 $3 $2
    StrCmp $5 $0 StrStr_done StrStr_loop

  StrStrReturn_notFound:
    StrCpy $2 -1

  StrStr_done:
    Pop $5
    Pop $4
    Pop $3
    Exch $2
    Exch 2
    Pop $0
    Pop $1
FunctionEnd
!macroend
!insertmacro StrStr ""
!insertmacro StrStr "un."

;====================================================
; IsNT - Returns 1 if the current system is NT, 0
;        otherwise.
;     Output: head of the stack
;====================================================
!macro IsNT un
Function ${un}IsNT
  Push $0
  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" CurrentVersion
  StrCmp $0 "" 0 IsNT_yes
  ; we are not NT.
  Pop $0
  Push 0
  Return

  IsNT_yes:
    ; NT!!!
    Pop $0
    Push 1
FunctionEnd
!macroend
!insertmacro IsNT ""
!insertmacro IsNT "un."

