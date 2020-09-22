#ifndef RADARE_H
#define RADARE_H

#include "models.h"

#include <r_core.h>
#include <QMutex>
#include <QThread>
#include <QWaitCondition>

class RadareWorker;

class RadareController : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY_MOVE(RadareController)

public:
    explicit RadareController(QObject *parent = nullptr);
    virtual ~RadareController();

    static RadareController *instance();

    Q_INVOKABLE void initialize(QString platformName, QString archName, int pointerSize);
    Q_INVOKABLE void deinitialize();
    Q_INVOKABLE int execute(QString command);

signals:
    void initializeRequest(RIOPlugin *plugin, QString platformName, QString archName, int pointerSize);
    void deinitializeRequest();
    void executeRequest(QString command, int requestId);
    void executeResponse(QString response, int requestId);

private slots:
    void onModulesChanged(Modules *newModules);
    void onModuleSynchronized(Module *module);
    void onFunctionsChanged(Functions *newFunctions);
    void onFunctionDiscovered(QString name, int offset, Module *module);
    void onFunctionRenamed(Function *func);

private:
    static RIODesc *onOpenWrapper(RIO *io, const char *pathname, int perm, int mode);
    RIODesc *onOpen(RIO *io, const char *pathname, int perm, int mode);
    static int onReadWrapper(RIO *io, RIODesc *fd, ut8 *buf, int count);
    int onRead(RIO *io, RIODesc *fd, ut8 *buf, int count);
    static ut64 onSeekWrapper(RIO *io, RIODesc *fd, ut64 offset, int whence);
    ut64 onSeek(RIO *io, RIODesc *fd, ut64 offset, int whence);
    static int onWriteWrapper(RIO *io, RIODesc *fd, const ut8 *buf, int count);
    int onWrite(RIO *io, RIODesc *fd, const ut8 *buf, int count);
    static bool onCheckWrapper(RIO *io, const char *pathname, bool many);
    bool onCheck(RIO *io, const char *pathname, bool many);

    RCore *m_core;
    RIOPlugin m_plugin;
    RadareWorker *m_worker;
    QThread m_thread;
    int m_nextRequestId;
    QMutex m_mutex;
    QWaitCondition m_cond;

    static RadareController *s_instance;
};

class RadareWorker : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY_MOVE(RadareWorker)

public:
    explicit RadareWorker(QObject *parent = nullptr);
    virtual ~RadareWorker();

public slots:
    void handleInitializeRequest(RIOPlugin *plugin, QString platformName, QString archName, int pointerSize);
    void handleDeinitializeRequest();
    void handleExecuteRequest(QString command, int requestId);

signals:
    void executeResponse(QString response, int requestId);

private:
    RCore *m_core;
};

#endif // RADARE_H
