TEMPLATE = app

QT += qml quick sql widgets
CONFIG += c++11

QTPLUGIN.bearer = -
QTPLUGIN.imageformats = -
QTPLUGIN.qmltooling = -

SOURCES += \
    main.cpp \
    nativepointer.cpp \
    models.cpp \
    models/functions.cpp \
    models/modules.cpp \
    router.cpp \
    models/tablemodel.cpp

RESOURCES += qml.qrc

# Additional import path used to resolve QML modules in Qt Creator's code model
QML_IMPORT_PATH =

QMAKE_INFO_PLIST = Info.plist

# Default rules for deployment.
include(deployment.pri)

HEADERS += \
    nativepointer.h \
    models.h \
    models/functions.h \
    models/modules.h \
    router.h \
    models/tablemodel.h

unix {
    PARTS = $$[QT_INSTALL_LIBS] libQt5Core.prl
    COREPRL = $$join(PARTS, "/")
}
win32 {
    PARTS = $$[QT_INSTALL_LIBS] Qt5Core.prl
    COREPRL = $$join(PARTS, "\\")
}
exists($$COREPRL) {
    include($$COREPRL)
    !contains(QMAKE_PRL_CONFIG, shared) {
        CONFIG += cryptoshark_static_qt
    }
}

cryptoshark_static_qt {
    DEFINES += CRYPTOSHARK_STATIC_QT=1
    RESOURCES += cryptoshark_qml_plugin_import.qrc
}

win32 {
    QMAKE_LFLAGS += /SAFESEH:NO
}
