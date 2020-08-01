@echo off

pushd %~dp0..\..\
set CRYPTOSHARK_SRCDIR=%CD%
pushd ..\
set CRYPTOSHARK_PARENTDIR=%CD%
set CRYPTOSHARK_DISTDIR=%CRYPTOSHARK_PARENTDIR%\dist
popd
popd

set CRYPTOSHARK_ARCH=%1
if "%CRYPTOSHARK_ARCH%" == "x86" (
  set CRYPTOSHARK_VCARCH=x86
  set CRYPTOSHARK_QTDIR=%CRYPTOSHARK_DISTDIR%\msvc2019
) else if "%CRYPTOSHARK_ARCH%" == "x86_64" (
  set CRYPTOSHARK_VCARCH=amd64
  set CRYPTOSHARK_QTDIR=%CRYPTOSHARK_DISTDIR%\msvc2019_64
) else (
  echo Usage: %~nx0 x86^|x86_64
  exit /b 1
)

set PATH=%CRYPTOSHARK_QTDIR%\bin;%CRYPTOSHARK_SRCDIR%\tools\windows;%PATH%

for /f "tokens=*" %%g in ('vswhere -latest -property installationPath') do (set vsdir=%%g)
set __VSCMD_ARG_NO_LOGO=1
call "%vsdir%\VC\Auxiliary\Build\vcvarsall.bat" %CRYPTOSHARK_VCARCH%
