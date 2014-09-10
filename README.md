# CryptoShark

Self-optimizing cross-platform code tracer based on dynamic recompilation,
powered by Frida and Capstone. Works at the machine code level, no source
code needed. Tags threads based on which APIs they use, showing you in
real-time what functions have been called, allowing you to study them by
carefully injecting logging and other side-effecty code.

## Screencast

[![ScreenShot](http://img.youtube.com/vi/hzDsxtcRavY/0.jpg)](https://www.youtube.com/watch?v=hzDsxtcRavY)

## Binaries

- [Windows](http://build.frida.re/frida/windows/Win32-Release/bin/cryptoshark-0.1.1.exe)
- [Mac](http://build.frida.re/frida/mac/CryptoShark-0.1.1.dmg)
- Linux: coming soon

## Building

### Building agent.js

#### Install build-time dependencies
    npm install -g gulp
    npm install

#### Build
    gulp build

#### Lint
    gulp lint

#### Watch while developing
    gulp watch

### Building the GUI

- Install [Qt 5.3.1](http://qt-project.org/downloads) or newer. (For now
  do not use their online installer, as it's still at 5.3.0, which has some
  rendering bugs.)

- Grab the latest frida-qml binaries from [here](http://build.frida.re/frida/).
  For example: http://build.frida.re/frida/mac/lib/qt5/qml/Frida/
  Download the entire directory and add it to your Qt installation's `qml`
  directory (on Mac it is typically: `~/Qt/5.3/clang_64/qml/`).
  (Only Windows and Mac binaries available for now. For Linux you'll have to
  build Frida yourself.)

- Open `cryptoshark.pro` with Qt Creator, select the `Release` configuration
  and hit `Run`.

### Building QT on Windows

#### Prerequisites

* MS Visual Studio 2013
* Windows SDK 8.1
* Git
* Perl
* Python
* nasm

Review all the paths in `tools\env.bat` to make sure everything matches your
system.

#### Building OpenSSL

- Enter the environment by running `tools\env.bat`.

- Download the latest openssl tarball and extract it in `tools\`.

- Change to that directory and run: `..\01-build-openssl.bat`.

#### Building Qt

- Enter the environment by running `tools\env.bat`.

- Get the qt5 repo: `git clone git://gitorious.org/qt/qt5.git qt5`

- Switch to the 5.4 branch:

```
cd qt5
git checkout 5.4
```

- Get the source code: `perl init-repository --no-webkit`

- Change working directory to `qt5\qtbase` and run: `..\..\02-build-qt.bat`

- Add qt5\qtbase\bin to your PATH: `set PATH=C:\src\cryptoshark\tools\qt5\qtbase\bin;%PATH%`

- Change working directory to `qt5\qtdeclarative`

- Cherry-pick a hotfix: `git fetch https://codereview.qt-project.org/qt/qtdeclarative refs/changes/28/94328/2 && git checkout FETCH_HEAD`

- Run: `qmake` followed by `nmake`

- Change working directory to `qt5\qtquickcontrols`

- Run: `qmake` followed by `nmake`