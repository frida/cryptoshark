TEMPLATE = app

macx {
    TARGET = Cryptoshark
} else {
    TARGET = cryptoshark
}

QT += qml quick quickcontrols2 sql widgets
CONFIG += c++11 qtquickcompiler

QTPLUGIN += qsvg
QTPLUGIN.bearer = -
QTPLUGIN.printsupport = -
QTPLUGIN.qmltooling = -

SOURCES += \
    main.cpp \
    nativepointer.cpp \
    models.cpp \
    models/functions.cpp \
    models/modules.cpp \
    radare.cpp \
    router.cpp

RESOURCES += app.qrc

QML_IMPORT_PATH = $$top_builddir/qml

QMAKE_INFO_PLIST = Info.plist

win32:RC_ICONS = images/icon.ico
macx:ICON = images/icon.icns

HEADERS += \
    nativepointer.h \
    models.h \
    models/functions.h \
    models/modules.h \
    radare.h \
    router.h

QMAKE_SUBSTITUTES += config.h.in

COMMIT_DESCRIPTION = $$system(git describe --tags --exclude "latest-*")
VERSION_STR = $$replace(COMMIT_DESCRIPTION, "-", ".")
VERSION = $$section(VERSION_STR, ., 0, 3)

win32 {
    PARTS = $$[QT_INSTALL_LIBS] Qt5Core.prl
    COREPRL = $$join(PARTS, "\\")
}
unix {
    PARTS = $$[QT_INSTALL_LIBS] libQt5Core.prl
    COREPRL = $$join(PARTS, "/")
}
exists($$COREPRL) {
    include($$COREPRL)
    !contains(QMAKE_PRL_CONFIG, shared) {
        CONFIG += cryptoshark_static_qt
    }
}

cryptoshark_static_qt {
    DEFINES += CRYPTOSHARK_STATIC_QT=1

    include($$top_srcdir/ext/frida-qml/frida-qml.pri)

    win32 {
        QMAKE_LFLAGS += /LTCG
    }
}

INCLUDEPATH += \
    $$OUT_PWD \
    $${R2_PREFIX}/include/libr \
    $${R2_PREFIX}/include/libr/sdb
LIBS_PRIVATE += \
    -L$${R2_PREFIX}/lib
r2_libs = \
    anal \
    asm \
    bin \
    bp \
    config \
    cons \
    core \
    crypto \
    debug \
    egg \
    flag \
    fs \
    hash \
    io \
    lang \
    magic \
    parse \
    reg \
    search \
    socket \
    syscall \
    util
win32 {
    for (name, r2_libs) {
        eval(LIBS_PRIVATE += libr_$${name}.a)
    }
    LIBS_PRIVATE += advapi32.lib wininet.lib ws2_32.lib
} else {
    for (name, r2_libs) {
        eval(LIBS_PRIVATE += -lr_$$name)
    }
}

unix {
    INSTALLS += target
    target.path = /usr/bin
}
linux {
    INSTALLS += desktop icon

    desktop.path = /usr/share/applications
    desktop.files = cryptoshark.desktop

    icon.path = /usr/share/icons/hicolor/scalable/apps
    icon.files = images/hicolor/scalable/apps/cryptoshark.svg

    resolutions = 16x16 32x32 48x48 64x64 128x128
    for (resolution, resolutions) {
        eval(INSTALLS += icon$${resolution})
        eval(icon$${resolution}.path = /usr/share/icons/hicolor/$${resolution}/apps)
        eval(icon$${resolution}.files = images/hicolor/$${resolution}/apps/cryptoshark.png)
    }
}
