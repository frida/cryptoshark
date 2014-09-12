perl -pi.bak -e "s,-O2 -MD,-Os -MT,g" mkspecs\win32-msvc2013\qmake.conf
set QMAKESPEC=
call configure -opensource -confirm-license -release -static -ltcg -no-sql-db2 -no-sql-ibase -no-sql-mysql -no-sql-oci -no-sql-odbc -no-sql-psql -no-sql-tds -nomake examples -nomake tests -no-style-windowsxp -no-style-fusion -opengl es2 -angle -qt-zlib -qt-libpng -qt-libjpeg -openssl-linked -I %CRYPTOSHARK_PREFIX%\include -L %CRYPTOSHARK_PREFIX%\lib OPENSSL_LIBS="-lssleay32 -llibeay32 -ladvapi32 -lcrypt32 -lgdi32 -luser32" -no-icu -no-dbus
nmake
