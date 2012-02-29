@echo off

setlocal
cd %0\..
call msvc-env.bat

start "" "%VSHOME%\Common7\IDE\devenv.exe" %SOLUTION%

endlocal
