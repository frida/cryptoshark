@echo off

setlocal EnableDelayedExpansion

set __CS_BUILDDIR_PATH=%1
if "!__CS_BUILDDIR_PATH!" == "" (
  set __CS_BUILDDIR_PATH=%CRYPTOSHARK_PARENTDIR%\build-qt-%CRYPTOSHARK_ARCH%
)

for %%I in ("!__CS_BUILDDIR_PATH!") do set "__CS_BUILDDIR_NAME=%%~nI"
for %%I in ("!__CS_BUILDDIR_PATH!\..") do set "__CS_BUILDDIR_PARENT=%%~fI"

pushd %CRYPTOSHARK_PARENTDIR%
setlocal
set PERLIO=:raw
perl -i -pe "s, stl exceptions,," qt5\qtbase\src\angle\src\config.pri || exit /b
perl -i -pe "s,_HAS_EXCEPTIONS=0 ,," qt5\qtbase\src\angle\src\config.pri || exit /b
perl -i -pe "s, WIN32 _ENABLE_EXTENDED_ALIGNED_STORAGE, WIN32 _HAS_EXCEPTIONS=0 _ENABLE_EXTENDED_ALIGNED_STORAGE," qt5\qtbase\mkspecs\common\msvc-desktop.conf || exit /b
endlocal
popd

pushd !__CS_BUILDDIR_PARENT!
if exist !__CS_BUILDDIR_NAME! goto already_built
echo on
mkdir !__CS_BUILDDIR_NAME! || exit /b
pushd !__CS_BUILDDIR_NAME!
call %CRYPTOSHARK_PARENTDIR%\qt5\configure ^
    -opensource -confirm-license ^
    -prefix %CRYPTOSHARK_QTDIR% ^
    -feature-relocatable ^
    -release ^
    -optimize-size ^
    -ltcg ^
    -static ^
    -static-runtime ^
    -mp ^
    -no-sql-db2 -no-sql-ibase -no-sql-mysql -no-sql-oci -no-sql-odbc -no-sql-psql -no-sql-tds ^
    -nomake examples ^
    -nomake tests ^
    -opengl es2 -angle ^
    -qt-zlib -qt-libpng -qt-libjpeg ^
    -no-openssl -schannel ^
    -no-icu ^
    -no-dbus ^
    -no-feature-qml-debug ^
    -no-feature-assistant ^
    -no-feature-designer ^
    -no-feature-distancefieldgenerator ^
    -no-feature-kmap2qmap ^
    -no-feature-linguist ^
    -no-feature-makeqpf ^
    -no-feature-pixeltool ^
    -no-feature-qev ^
    -no-feature-qtattributionsscanner ^
    -no-feature-qtdiag ^
    -no-feature-qtpaths ^
    -no-feature-qtplugininfo ^
    || exit /b
nmake || exit /b
nmake install || exit /b
popd
popd

exit /b 0

:already_built
echo Already built. Wipe !__CS_BUILDDIR_PATH! to rebuild.
popd
exit /b 0
