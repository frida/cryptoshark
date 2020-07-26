@echo off

@cd %~dp0..\..\
set CRYPTOSHARK_SRCDIR=%CD%
@cd ..\
set CRYPTOSHARK_PREFIX=%CD%\dist
set PATH=%CRYPTOSHARK_PREFIX%\bin;%CRYPTOSHARK_SRCDIR%\tools\windows;%PATH%

for /f "tokens=*" %%g in ('vswhere -latest -property installationPath') do (set vsdir=%%g)
call "%vsdir%\VC\Auxiliary\Build\vcvarsall.bat" amd64

cmd
