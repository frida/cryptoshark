set PERLIO=:raw
perl -i -pe "s, stl exceptions,,g" qt5\qtbase\src\angle\src\config.pri || exit /b
set PERLIO=

mkdir qt-build || exit /b
cd qt-build
call ..\qt5\configure ^
    -opensource -confirm-license ^
    -prefix %CRYPTOSHARK_PREFIX% ^
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
    || exit /b
nmake || exit /b
