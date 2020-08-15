#include "models.h"
#include "nativepointer.h"
#include "router.h"

#include <QApplication>
#include <QFontDatabase>
#include <QQmlApplicationEngine>
#include <QQuickStyle>
#include <QtQml>

#ifdef Q_OS_WINDOWS
# define CRYPTOSHARK_STYLE "Universal"
#else
# define CRYPTOSHARK_STYLE "Fusion"
#endif

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
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QApplication app(argc, argv);

    qRegisterMetaType<Modules *>("Modules *");
    qRegisterMetaType<Module *>("Module *");
    qRegisterMetaType<Functions *>("Functions *");
    qRegisterMetaType<Function *>("Function *");

    qmlRegisterSingletonType<NativePointer>("Cryptoshark", 1, 0, "Router", createRouterSingleton);
    qmlRegisterSingletonType<NativePointer>("Cryptoshark", 1, 0, "Models", createModelsSingleton);
    qmlRegisterSingletonType<NativePointer>("Cryptoshark", 1, 0, "NativePointer", createNativePointerSingleton);

    QQuickStyle::setStyle(CRYPTOSHARK_STYLE);

    QQmlApplicationEngine engine;
    auto fixedFont = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    engine.rootContext()->setContextProperty("fixedFont", fixedFont);
#ifdef CRYPTOSHARK_STATIC_QT
    engine.setImportPathList(QStringList(QStringLiteral("qrc:/qt-project.org/imports")));
#else
    QDir candidate = QDir(QCoreApplication::applicationDirPath());
    const int maxLevelsUp = 5;
    for (int i = 0; i != maxLevelsUp; i++) {
        if (candidate.cd("qml")) {
            engine.addImportPath(candidate.absolutePath());
            break;
        }
        if (!candidate.cdUp())
            break;
    }
#endif
    engine.load(QUrl(QStringLiteral("qrc:///ui/main.qml")));

    return app.exec();
}
