git clone git://code.qt.io/qt/qt5.git || exit /b
cd qt5
git checkout 5.15 || exit /b
perl init-repository --module-subset=qtbase,qtdeclarative,qtquickcontrols,qtquickcontrols2 || exit /b
cd ..
