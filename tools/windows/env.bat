@echo off

@cd %~dp0..\..\
set CRYPTOSHARK_SRCDIR=%CD%
@cd ..\
set CRYPTOSHARK_PREFIX=%CD%\dist
set QT_PREFIX=%CD%\qt5\qtbase
set PATH=%QT_PREFIX%\bin;%PATH%

for /f "tokens=*" %%g in ('%CRYPTOSHARK_SRCDIR%\tools\windows\vswhere.exe -latest -property installationPath') do (set vsdir=%%g)
call "%vsdir%\VC\Auxiliary\Build\vcvarsall.bat" amd64

cmd
