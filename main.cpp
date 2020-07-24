#include "models.h"
#include "nativepointer.h"
#include "router.h"

#include <QApplication>
#include <QFontDatabase>
#include <QQmlApplicationEngine>
#include <QtQml>

static QObject *createRouterSingleton(QQmlEngine *engine, QJSEngine *scriptEngine)
{
    Q_UNUSED(engine);
    Q_UNUSED(scriptEngine);

    return Router::instance();
}

static QObject *createModelsSingleton(QQmlEngine *engine, QJSEngine *scriptEngine)
{
    Q_UNUSED(engine);
    Q_UNUSED(scriptEngine);

    return Models::instance();
}

static QObject *createNativePointerSingleton(QQmlEngine *engine, QJSEngine *scriptEngine)
{
    Q_UNUSED(engine);
    Q_UNUSED(scriptEngine);

    return NativePointer::instance();
}

int main(int argc, char *argv[])
{
#ifdef CRYPTOSHARK_STATIC_QT
    QApplication::setLibraryPaths(QStringList());
#endif
    QApplication app(argc, argv);

    qRegisterMetaType<Modules *>("Modules *");
    qRegisterMetaType<Module *>("Module *");
    qRegisterMetaType<Functions *>("Functions *");
    qRegisterMetaType<Function *>("Function *");

    qmlRegisterSingletonType<NativePointer>("CryptoShark", 1, 0, "Router", createRouterSingleton);
    qmlRegisterSingletonType<NativePointer>("CryptoShark", 1, 0, "Models", createModelsSingleton);
    qmlRegisterSingletonType<NativePointer>("CryptoShark", 1, 0, "NativePointer", createNativePointerSingleton);

    QQmlApplicationEngine engine;
    auto fixedFont = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    engine.rootContext()->setContextProperty("fixedFont", fixedFont);
#ifdef CRYPTOSHARK_STATIC_QT
    engine.setImportPathList(QStringList(QStringLiteral("qrc:/imports")));
#endif
    engine.load(QUrl(QStringLiteral("qrc:///main.qml")));

    return app.exec();
}
