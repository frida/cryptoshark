#include "nativepointer.h"

#include <QApplication>
#include <QQmlApplicationEngine>
#include <QtQml>

static QObject *createNativePointerSingleton(QQmlEngine *engine, QJSEngine *scriptEngine)
{
    Q_UNUSED(engine);
    Q_UNUSED(scriptEngine);

    return new NativePointer();
}

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    qmlRegisterSingletonType<NativePointer>("CryptoShark", 1, 0, "NativePointer", createNativePointerSingleton);

    QQmlApplicationEngine engine;
    engine.load(QUrl(QStringLiteral("qrc:///main.qml")));

    return app.exec();
}
