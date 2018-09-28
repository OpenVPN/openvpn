@echo off

setlocal
cd /d %0\..
call msvc-env.bat

if exist "%VSHOME%\Common7\IDE\VCExpress.exe" (
	set IDE=%VSHOME%\Common7\IDE\VCExpress.exe
) else if exist "%VSHOME%\Common7\IDE\devenv.exe" (
	set IDE=%VSHOME%\Common7\IDE\devenv.exe
) else if exist "%VCHOME%\Auxiliary\Build\vcvars64.bat" (
	call "%VCHOME%\Auxiliary\Build\vcvars64.bat"
) else (
	echo "Cannot detect visual studio environment"
	goto error
)
start "" "%IDE%" "%SOLUTION%"

exit /b 0
goto end

:error
exit /b 1
goto end

:end

endlocal
