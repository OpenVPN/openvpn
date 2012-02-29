@echo off

rem Copyright (C) 2008-2012 Alon Bar-Lev <alon.barlev@gmail.com>

call msvc-env.bat

@rem this stupid command needed for SetEnv.cmd to operate
setlocal ENABLEDELAYEDEXPANSION

set PLATFORMS=Win32
set CONFIGURATIONS=Release

call "%VCHOME%\bin\vcvars32.bat"

for %%p in (%PLATFORMS%) do (
	for %%c in (%CONFIGURATIONS%) do (
		rmdir /q /s %SOURCEBASE%\%%p\%%c > nul 2>&1

		vcbuild /errfile:error.log /showenv %SOLUTION% /rebuild /platform:%%p "%%c|%%p"
		for %%f in (error.log) do if %%~zf GTR 0 goto error
	)
)

exit /b 0
goto end

:error
if "%1" NEQ "batch" pause
exit /b 1
goto end

:end

endlocal
