#!/bin/sh
./configure -prefix $HOME/Qt/5.3/clang_64_static -opensource -confirm-license -release -force-debug-info -no-strip -static -no-sql-db2 -no-sql-ibase -no-sql-mysql -no-sql-oci -no-sql-odbc -no-sql-psql -no-sql-tds -nomake examples -nomake tests -qt-zlib -qt-libpng -qt-libjpeg -no-freetype -no-harfbuzz -openssl-linked -no-icu -no-fontconfig -no-dbus
make -j8
