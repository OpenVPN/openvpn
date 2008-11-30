; ExtractAuxFile
;   Copies a text file appended to the end of the installer EXE
;   to a caller-specified output file.
; Inputs:
;   output_filename (string) -- the output filename
; Outputs:
;   status (int) -- 0 on success, > 0 on failure

Function ExtractAuxFile
  Exch $R1            ; output filename argument
  ; locals
  Push $R0
  Push $1
  Push $2
  Push $3
  Push $4
  Push $5
 
  ClearErrors

  ; $R0 = installer filename
  System::Call 'kernel32::GetModuleFileNameA(i 0, t .R0, i 1024) i r1'

  ; $1 = open (installer_exe) for read
  FileOpen $1 $R0 r
  IfErrors openin_err

  ; seek to EOF - 8 (start of 8-byte trailer)
  ; $3 = seekpos
  IntOp $2 0 - 8
  FileSeek $1 $2 END $3

  ; $4 = -(content_length(auxfile) + 8)
  ; seek position from end of file to beginning of content
  FileReadByte $1 $4
  FileReadByte $1 $5
  IfErrors readlen_err
  IntOp $5 $5 << 8
  IntOp $4 $4 + $5
  IntOp $4 $4 + 8
  IntOp $4 0 - $4

  ; verify magic sequence 0xae, 0xb7, 0x03, 0x69, 0x42, 0x11
  FileReadByte $1 $5
  IntCmp $5 0xae 0 magic_err magic_err
  FileReadByte $1 $5
  IntCmp $5 0xb7 0 magic_err magic_err
  FileReadByte $1 $5
  IntCmp $5 0x03 0 magic_err magic_err
  FileReadByte $1 $5
  IntCmp $5 0x69 0 magic_err magic_err
  FileReadByte $1 $5
  IntCmp $5 0x42 0 magic_err magic_err
  FileReadByte $1 $5
  IntCmp $5 0x11 0 magic_err magic_err
  IfErrors magic_err

  ; seek to start of auxfile data
  FileSeek $1 $4 END

  ; $2 = open (output_filename) for write
  FileOpen $2 $R1 w
  IfErrors openout_err

loop:
  ; check if we are finished
  FileSeek $1 0 CUR $5
  IntCmp $5 $3 success 0 overshot_err

  ; copy next line from .exe to output file
  FileRead $1 $5
  IfErrors read_err
  FileWrite $2 $5
  IfErrors write_err
  goto loop

success:
  IntOp $R1 0 + 0
  goto fin

openin_err:
  IntOp $R1 1 + 0
  goto fin

openout_err:
  IntOp $R1 2 + 0
  goto fin

readlen_err:
  IntOp $R1 3 + 0
  goto fin

overshot_err:
  IntOp $R1 4 + 0
  goto fin

read_err:
  IntOp $R1 5 + 0
  goto fin

write_err:
  IntOp $R1 6 + 0
  goto fin

magic_err:
  IntOp $R1 7 + 0
  goto fin

fin:
  Pop $5
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $R0
  Exch $R1
FunctionEnd
