@echo off

cd %~dp0..\..\
set CRYPTOSHARK_SRCDIR=%CD%
cd ..\
set CRYPTOSHARK_ARCH=%1
set CRYPTOSHARK_PREFIX=%CD%\dist\%3
set PATH=%CRYPTOSHARK_PREFIX%\bin;%CRYPTOSHARK_SRCDIR%\tools\windows;%PATH%

for /f "tokens=*" %%g in ('vswhere -latest -property installationPath') do (set vsdir=%%g)
call "%vsdir%\VC\Auxiliary\Build\vcvarsall.bat" %2

cmd
