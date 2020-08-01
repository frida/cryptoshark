@echo off

pushd %CRYPTOSHARK_PARENTDIR%

setlocal
set PERLIO=:raw
perl -i -pe "s, stl exceptions,," qt5\qtbase\src\angle\src\config.pri || exit /b
perl -i -pe "s,_HAS_EXCEPTIONS=0 ,," qt5\qtbase\src\angle\src\config.pri || exit /b
perl -i -pe "s, WIN32 _ENABLE_EXTENDED_ALIGNED_STORAGE, WIN32 _HAS_EXCEPTIONS=0 _ENABLE_EXTENDED_ALIGNED_STORAGE," qt5\qtbase\mkspecs\common\msvc-desktop.conf || exit /b
endlocal

if exist build-qt-%CRYPTOSHARK_ARCH% goto already_built
echo on
mkdir build-qt-%CRYPTOSHARK_ARCH% || exit /b
pushd build-qt-%CRYPTOSHARK_ARCH%
call ..\qt5\configure ^
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
    || exit /b
nmake || exit /b
nmake install || exit /b
popd

popd
exit /b 0

:already_built
echo Already built. Wipe build-qt-%CRYPTOSHARK_ARCH% to rebuild.
popd
exit /b 0
