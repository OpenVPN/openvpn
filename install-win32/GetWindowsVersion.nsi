; Turn off old selected section
; GetWindowsVersion
;
; Based on Yazno's function
; Updated by Joost Verburg
; Updated for Windows 98 SE by Matthew Win Tibbals 5-21-03
; Updated for Vista by Joe Cincotta 12-2-07
;
; Returns on top of stack
;
; Windows Version (95, 98, ME, NT x.x, 2000, XP, 2003, VISTA)
; or
; '' (Unknown Windows Version)
;
; Usage:
;   Call GetWindowsVersion
;   Pop $R0
;   ; at this point $R0 is "NT 4.0" or whatnot
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
Function GetWindowsVersion
 
  Push $R0
  Push $R1
 
  ClearErrors
 
  ReadRegStr $R0 HKLM \
  "SOFTWARE\Microsoft\Windows NT\CurrentVersion" CurrentVersion
 
  IfErrors 0 lbl_winnt
 
  ; we are not NT
  ReadRegStr $R0 HKLM \
  "SOFTWARE\Microsoft\Windows\CurrentVersion" VersionNumber
 
  StrCpy $R1 $R0 1
  StrCmp $R1 '4' 0 lbl_error
 
  StrCpy $R1 $R0 3
 
  StrCmp $R1 '4.0' lbl_win32_95
  StrCmp $R1 '4.9' lbl_win32_ME lbl_win32_98
 
  lbl_win32_95:
    StrCpy $R0 '95'
  Goto lbl_done
 
  lbl_win32_98:
;;beginning of additions to support win 98 SE
    push $R0
    push "."
    call strstr
    pop $R0
    StrCpy $R0 $R0 "" 1
    StrCmp $R0 "10.2222" lbl_win32_98SE
    StrCpy $R0 '98'  ;;this line was not added
  Goto lbl_done      ;;this line was not added either
 
  lbl_win32_98SE:
    StrCpy $R0 '98 SE'
  Goto lbl_done
;;end of additions to support win 98 SE
  lbl_win32_ME:
    StrCpy $R0 'ME'
  Goto lbl_done
 
  lbl_winnt:
 
  StrCpy $R1 $R0 1
 
  StrCmp $R1 '3' lbl_winnt_x
  StrCmp $R1 '4' lbl_winnt_x
 
  StrCpy $R1 $R0 3
 
  StrCmp $R1 '5.0' lbl_winnt_2000
  StrCmp $R1 '5.1' lbl_winnt_XP
  StrCmp $R1 '5.2' lbl_winnt_2003
  StrCmp $R1 '6.0' lbl_winnt_VISTA lbl_error
 
  lbl_winnt_x:
    StrCpy $R0 "NT $R0" 6
  Goto lbl_done
 
  lbl_winnt_2000:
    Strcpy $R0 '2000'
  Goto lbl_done
 
  lbl_winnt_XP:
    Strcpy $R0 'XP'
  Goto lbl_done
 
  lbl_winnt_2003:
    Strcpy $R0 '2003'
  Goto lbl_done
 
  lbl_winnt_VISTA:
    Strcpy $R0 'VISTA'
  Goto lbl_done
 
  lbl_error:
    Strcpy $R0 ''
  lbl_done:
 
  Pop $R1
  Exch $R0
 
FunctionEnd
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
