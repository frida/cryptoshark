@echo off

setlocal EnableDelayedExpansion

set __CS_FRIDA_VERSION=12.11.12

set __CS_ARCH=%1
if "!__CS_ARCH!" == "" (
  if defined CRYPTOSHARK_ARCH (
    set __CS_ARCH=%CRYPTOSHARK_ARCH%
  ) else (
    set __CS_ARCH=x86_64
  )
)

pushd %~dp0

if not exist ext\frida-qml\frida-qml.pri (
  echo.
  echo ***
  echo *** Fetching frida-qml
  echo ***
  git submodule init
  git submodule update || exit /b
)

set __CS_DEVKITURL=https://github.com/frida/frida/releases/download/!__CS_FRIDA_VERSION!/frida-core-devkit-!__CS_FRIDA_VERSION!-windows-!__CS_ARCH!.exe
set __CS_DEVKITDIR=ext\frida-core\!__CS_ARCH!
if not exist !__CS_DEVKITDIR!\frida-core.lib (
  echo.
  echo ***
  echo *** Fetching frida-core devkit for !__CS_ARCH!
  echo ***
  rmdir /s /q !__CS_DEVKITDIR! 2>nul
  mkdir !__CS_DEVKITDIR! || exit /b
  pushd !__CS_DEVKITDIR!
  powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; " ^
      "Invoke-WebRequest -Uri !__CS_DEVKITURL! -OutFile devkit.exe" || exit /b
  devkit.exe || exit /b
  del devkit.exe
  popd
)

if not exist ext\radare2\build\priv_install_dir\lib\r_core.lib (
  echo.
  echo ***
  echo *** Building r2
  echo ***
  pushd ext\radare2
  rmdir /s /q build 2>nul
  meson setup build ^
      --prefix="$(pwd)/build/priv_install_dir" ^
      --backend=ninja ^
      --default-library=static ^
      -Doptimization=s ^
      -Db_ndebug=true ^
      -Duse_capstone5=true ^
      -Duse_libuv=false ^
      -Duse_sys_magic=false ^
      -Ddebugger=false ^
      -Denable_tests=false ^
      -Denable_r2r=false ^
      || exit /b
  ninja -C build install || exit /b
  popd
)

if not exist app\agent.js (
  echo.
  echo ***
  echo *** Building agent
  echo ***
  pushd app\agent
  npm install || exit /b
  popd
)

popd

endlocal
