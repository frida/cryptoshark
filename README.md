# CryptoShark

An open source cross-platform debugger powered by Frida and Capstone.

## Screencast

[![ScreenShot](http://img.youtube.com/vi/hzDsxtcRavY/0.jpg)](https://www.youtube.com/watch?v=hzDsxtcRavY)

## Binaries

- [Windows](http://build.frida.re/frida/windows/Win32-Release/bin/cryptoshark-0.1.1.exe)
- Mac: coming soon
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

- Grab the latest frida-qml binaries from [http://build.frida.re/frida/](here).
  For example: http://build.frida.re/frida/mac/lib/qt5/qml/Frida/
  Download the entire directory and add it to your Qt installation's `qml`
  directory (on Mac it is typically: `~/Qt/5.3/clang_64/qml/`).
  (Only Windows and Mac binaries available for now. For Linux you'll have to
  build Frida yourself.)

- Open `cryptoshark.pro` with Qt Creator, select the `Release` configuration
  and hit `Run`.
