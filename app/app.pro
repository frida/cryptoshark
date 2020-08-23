TEMPLATE = app

macx {
    TARGET = Cryptoshark
} else {
    TARGET = cryptoshark
}

QT += qml quick quickcontrols2 sql widgets
CONFIG += c++11 qtquickcompiler

QTPLUGIN.bearer = -
QTPLUGIN.imageformats = -
QTPLUGIN.qmltooling = -

SOURCES += \
    main.cpp \
    nativepointer.cpp \
    models.cpp \
    models/functions.cpp \
    models/modules.cpp \
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
    router.h

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
