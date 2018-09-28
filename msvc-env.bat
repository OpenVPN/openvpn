@echo off

rem Put your own settings at msvc-env-local.bat
if exist msvc-env-local.bat call msvc-env-local.bat

if "%ProgramFiles(x86)%"=="" set ProgramFiles(x86)=%ProgramFiles%
if "%VSCOMNTOOLS%"=="" set VSCOMNTOOLS=%ProgramFiles(x86)%\Microsoft Visual Studio\2017\Professional\Common7\Tools
if not exist "%VSCOMNTOOLS%" set VSCOMNTOOLS=%ProgramFiles(x86)%\Microsoft Visual Studio\2017\Community\Common7\Tools
if "%VSHOME%"=="" SET VSHOME=%VSCOMNTOOLS%\..\..
if "%VCHOME%"=="" SET VCHOME=%VSHOME%\VC

set SOURCEBASE=%cd%
set SOLUTION=openvpn.sln
set CPPFLAGS=%CPPFLAGS%;_CRT_SECURE_NO_WARNINGS;WIN32_LEAN_AND_MEAN;_CRT_NONSTDC_NO_WARNINGS;_CRT_SECURE_NO_WARNINGS
set CPPFLAGS=%CPPFLAGS%;NTDDI_VERSION=NTDDI_VISTA;_WIN32_WINNT=_WIN32_WINNT_VISTA
set CPPFLAGS=%CPPFLAGS%;
set CPPFLAGS=%CPPFLAGS%;%EXTRA_CPPFLAGS%

if exist config-msvc-local.h set CPPFLAGS="%CPPFLAGS%;HAVE_CONFIG_MSVC_LOCAL_H"

if "%OPENVPN_DEPROOT%" == "" set OPENVPN_DEPROOT=c:\Temp\openvpn-deps
if "%OPENSSL_HOME%" == "" set OPENSSL_HOME=%OPENVPN_DEPROOT%
if "%LZO_HOME%" == "" set LZO_HOME=%OPENVPN_DEPROOT%
if "%PKCS11H_HOME%" == "" set PKCS11H_HOME=%OPENVPN_DEPROOT%
if "%TAP_WINDOWS_HOME%" == "" set TAP_WINDOWS_HOME=%OPENVPN_DEPROOT%

if not exist "%OPENSSL_HOME%" echo WARNING: openssl '%OPENSSL_HOME%' does not exist
if not exist "%LZO_HOME%" echo WARNING: lzo '%LZO_HOME%' does not exist
if not exist "%PKCS11H_HOME%" echo WARNING: pkcs11-helper '%PKCS11H_HOME%' does not exist
if not exist "%TAP_WINDOWS_HOME%" echo WARNING: tap-windows '%TAP_WINDOWS_HOME%' does not exist
