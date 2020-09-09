@echo off

setlocal EnableDelayedExpansion

set __CS_BUILDDIR_PATH=%1
if "!__CS_BUILDDIR_PATH!" == "" (
  set __CS_BUILDDIR_PATH=%CRYPTOSHARK_SRCDIR%\ext\radare2\build
)

if exist !__CS_BUILDDIR_PATH! goto compile
pushd %CRYPTOSHARK_SRCDIR%\ext\radare2
echo on
meson setup "!__CS_BUILDDIR_PATH!" ^
    --prefix="!__CS_BUILDDIR_PATH!\priv_install_dir" ^
    --backend=ninja ^
    --default-library=static ^
    -Doptimization=s ^
    -Db_ndebug=true ^
    -Dcli=disabled ^
    -Duse_capstone_version=v5 ^
    -Duse_libuv=false ^
    -Duse_sys_magic=false ^
    -Ddebugger=false ^
    -Denable_tests=false ^
    -Denable_r2r=false ^
    || exit /b
@echo off
popd

:compile
ninja -C "!__CS_BUILDDIR_PATH!" install || exit /b

exit /b 0
