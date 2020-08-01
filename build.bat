@echo off

setlocal EnableDelayedExpansion

set __CS_ARCH=%1

if defined CRYPTOSHARK_ARCH (
  if not "!__CS_ARCH!" == "" (
    echo Architecture cannot be specified when run inside environment.
    exit /b 1
  )
) else (
  if "!__CS_ARCH!" == "" (
    set __CS_ARCH=x86_64
  )
  call %~dp0tools\windows\activate-env.bat !__CS_ARCH! || exit /b
)

where /q qmake
if errorlevel 1 (
  echo Qt not found. Please ensure its bin directory is on your PATH.
  exit /b 1
)

call %~dp0bootstrap.bat !__CS_ARCH! || exit /b

pushd "%CRYPTOSHARK_PARENTDIR%"
mkdir build-cryptoshark-%CRYPTOSHARK_ARCH% 2>nul
pushd build-cryptoshark-%CRYPTOSHARK_ARCH% || exit /b

if not exist .\Makefile (
  qmake CONFIG+=silent "%CRYPTOSHARK_SRCDIR%" || exit /b
)

nmake || exit /b

popd
popd

endlocal
