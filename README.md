# Cryptoshark

Self-optimizing cross-platform code tracer based on dynamic recompilation,
powered by Frida and Capstone. Works at the machine code level, no source
code needed. Tags threads based on which APIs they use, showing you in
real-time what functions have been called, allowing you to study them by
carefully injecting logging and other side-effecty code.

## Screencast

[![ScreenShot](http://img.youtube.com/vi/hzDsxtcRavY/0.jpg)](https://www.youtube.com/watch?v=hzDsxtcRavY)

## Binaries

Get them at: https://github.com/frida/cryptoshark/releases

## Development workflow

First, make sure you have a Qt >= 5.15 SDK installed and that its
`bin`-directory is on your PATH.  Also make sure you have Node.js
10 or newer.

### Building the app: Command Line

Run the `build` script.  This will output a binary at:

- Windows: `..\build-cryptoshark-x86_64\app\release\cryptoshark.exe`
- macOS: `../build-cryptoshark-x86_64/app/Cryptoshark.app/Contents/MacOS/Cryptoshark`
- Linux: `../build-cryptoshark-x86_64/app/cryptoshark`

### Building the app: Qt Creator

Run the `bootstrap` script and then open `cryptoshark.pro` in Qt Creator.

### Building agent.js

This is the blob of JavaScript that Cryptoshark injects into target processes.

For a one-off build:

    $ cd app/agent
    $ npm run build

And to watch while developing:

    $ cd app/agent
    $ npm run watch

This will monitor the TypeScript source code and incrementally compile
`app/agent.js`. Note that the agent is included as a resource, so remember to
`build`.

## Building a portable binary

In order to build a portable binary we will need a static build of Qt. This is
not recommended for development due to the prolonged linking times, but it is
very useful for generating a portable Cryptoshark binary without any external
dependencies.

### Windows

#### Prerequisites

* MS Visual Studio 2019
* Git
* Strawberry Perl
* Python (Note: Installation location cannot contain spaces due to bugs in Qt's
  build system.)

#### Building Qt

Run `tools\windows\env-x86_64.bat` to enter the environment, then:

- Get the source code by running: `get-qt`

- And finally: `build-qt`

#### Building Cryptoshark

- Change to the root directory of this repo.

- Run `build`.

- A fresh new portable binary is now at:

    ..\build-cryptoshark-x86_64\app\release\cryptoshark.exe

### macOS

#### Prerequisites

* Xcode

#### Building Qt

Run `. tools/macos/activate-env` to enter the environment, then:

- Get the source code by running: `get-qt`

- And finally: `build-qt`

#### Building Cryptoshark

- Change to the root directory of this repo.

- Run `./build`.

- A fresh new portable binary is now at:

    ../build-cryptoshark-$arch/app/Cryptoshark.app/Contents/MacOS/Cryptoshark
