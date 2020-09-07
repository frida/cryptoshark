#include "radare.h"

#include "router.h"

#include <cstring>
#include <QThread>

RadareController *RadareController::s_instance = nullptr;

static QString archFromFrida(QString name);

RadareController::RadareController(QObject *parent) :
    QObject(parent),
    m_core(r_core_new()),
    m_worker(new RadareWorker(m_core)),
    m_nextRequestId(1)
{
    std::memset(&m_plugin, 0, sizeof(m_plugin));
    m_plugin.name = "cryptoshark";
    m_plugin.desc = "I/O plugin for accessing remote process memory";
    m_plugin.license = "wxWindows Library Licence, Version 3.1";
    m_plugin.open = onOpenWrapper;
    m_plugin.read = onReadWrapper;
    m_plugin.lseek = onSeekWrapper;
    m_plugin.write = onWriteWrapper;
    m_plugin.check = onCheckWrapper;
    r_io_plugin_add(m_core->io, &m_plugin);

    m_worker->moveToThread(&m_thread);
    connect(&m_thread, &QThread::finished, m_worker, &QObject::deleteLater);
    connect(this, &RadareController::initializeRequest, m_worker, &RadareWorker::handleInitializeRequest);
    connect(this, &RadareController::executeRequest, m_worker, &RadareWorker::handleExecuteRequest);
    connect(m_worker, &RadareWorker::executeResponse, this, &RadareController::executeResponse);
    m_thread.start();

    auto models = Models::instance();
    connect(models, &Models::modulesChanged, this, &RadareController::onModulesChanged);
    connect(models, &Models::functionsChanged, this, &RadareController::onFunctionsChanged);
}

RadareController::~RadareController()
{
    m_thread.quit();
    m_thread.wait();
    r_core_free(m_core);

    s_instance = nullptr;
}

RadareController *RadareController::instance()
{
    if (s_instance == nullptr)
        s_instance = new RadareController();
    return s_instance;
}

void RadareController::initialize(QString platformName, QString archName, int pointerSize)
{
    emit initializeRequest(platformName, archName, pointerSize);
}

int RadareController::execute(QString command)
{
    auto id = m_nextRequestId++;
    emit executeRequest(command, id);
    return id;
}

void RadareController::onModulesChanged(Modules *newModules)
{
    if (newModules == nullptr)
        return;

    connect(newModules, &Modules::synchronized, this, &RadareController::onModuleSynchronized);
}

void RadareController::onModuleSynchronized(Module *module)
{
    QStringList commands;
    module->enumerateFunctionEntries([&] (QString name, quint64 address) {
        // TODO: Use API instead, which is faster and means we don't have to quote the name – a detail ignored here.
        commands << QStringLiteral("af+ 0x") + QString::number(address, 16) + QStringLiteral(" ") + name;
    });
    if (commands.empty())
        return;
    execute(commands.join(';'));
}

void RadareController::onFunctionsChanged(Functions *newFunctions)
{
    if (newFunctions == nullptr)
        return;

    connect(newFunctions, &Functions::discovered, this, &RadareController::onFunctionDiscovered);
    connect(newFunctions, &Functions::renamed, this, &RadareController::onFunctionRenamed);
}

void RadareController::onFunctionDiscovered(QString name, int offset, Module *module)
{
    const quint64 address = module->base() + offset;
    // TODO: Use API instead, which is faster and means we don't have to quote the name – a detail ignored here.
    execute(QStringLiteral("af+ 0x") + QString::number(address, 16) + QStringLiteral(" ") + name);
}

void RadareController::onFunctionRenamed(Function *function)
{
    // TODO: Use API instead, which is faster and means we don't have to quote the name – a detail ignored here.
    execute(QStringLiteral("afn ") + function->name() + " " + function->address());
}

RIODesc *RadareController::onOpenWrapper(RIO *io, const char *pathname, int perm, int mode)
{
    return instance()->onOpen(io, pathname, perm, mode);
}

RIODesc *RadareController::onOpen(RIO *io, const char *pathname, int perm, int mode)
{
    Q_UNUSED(perm);

    return r_io_desc_new(io, &m_plugin, pathname, R_PERM_RWX, mode, this);
}

int RadareController::onReadWrapper(RIO *io, RIODesc *fd, ut8 *buf, int count)
{
    return instance()->onRead(io, fd, buf, count);
}

int RadareController::onRead(RIO *io, RIODesc *fd, ut8 *buf, int count)
{
    Q_UNUSED(fd);

    int n = -1;

    auto request = Router::instance()->request(QStringLiteral("memory:read"), {
                                                   QString::number(io->off),
                                                   count
                                               });
    QObject::connect(request, &Request::completed, [=, &n] (QVariant result, RequestError *error) {
        QMutexLocker locker(&m_mutex);
        if (error == nullptr) {
            QByteArray data = result.toByteArray();
            n = data.size();
            ::memcpy(buf, data.data(), n);
        } else {
            n = 0;
        }
        m_cond.wakeAll();
    });

    {
        QMutexLocker locker(&m_mutex);
        while (n == -1)
            m_cond.wait(&m_mutex);
    }

    return n;
}

ut64 RadareController::onSeekWrapper(RIO *io, RIODesc *fd, ut64 offset, int whence)
{
    return instance()->onSeek(io, fd, offset, whence);
}

ut64 RadareController::onSeek(RIO *io, RIODesc *fd, ut64 offset, int whence)
{
    Q_UNUSED(fd);

    switch (whence) {
    case SEEK_SET:
        io->off = offset;
        break;
    case SEEK_CUR:
        io->off += (st64) offset;
        break;
    case SEEK_END:
        io->off = UT64_MAX;
        break;
    }

    return io->off;
}

int RadareController::onWriteWrapper(RIO *io, RIODesc *fd, const ut8 *buf, int count)
{
    return instance()->onWrite(io, fd, buf, count);
}

int RadareController::onWrite(RIO *io, RIODesc *fd, const ut8 *buf, int count)
{
    Q_UNUSED(io);
    Q_UNUSED(fd);
    Q_UNUSED(buf);
    Q_UNUSED(count);

    qDebug() << "onWrite(): FIXME";

    return -1;
}

bool RadareController::onCheckWrapper(RIO *io, const char *pathname, bool many)
{
    return instance()->onCheck(io, pathname, many);
}

bool RadareController::onCheck(RIO *io, const char *pathname, bool many)
{
    Q_UNUSED(io);
    Q_UNUSED(many);

    return r_str_startswith(pathname, "cs://");
}

RadareWorker::RadareWorker(RCore *core, QObject *parent) :
    QObject(parent),
    m_state(State::Created),
    m_core(core)
{
}

void RadareWorker::handleInitializeRequest(QString platformName, QString archName, int pointerSize)
{
    Q_UNUSED(platformName);

    RConfig *config = m_core->config;

    if (m_state == State::Created) {
        r_core_task_sync_begin(&m_core->tasks);

        const char *uri = "cs:///";
        const ut64 loadAddress = 0;
        r_core_file_open(m_core, uri, R_PERM_RWX, loadAddress);
        r_core_cmd0(m_core, "=!");
        r_core_bin_load(m_core, uri, loadAddress);

        r_config_set(config, "scr.html", "true");
        r_config_set_i(config, "scr.color", COLOR_MODE_16M);
        r_config_set(config, "asm.emu", "true");
        r_config_set(config, "emu.str", "true");

        m_state = State::Initialized;
    }

    QByteArray radareOSName = platformName.toUtf8();
    r_config_set(config, "asm.os", radareOSName.data());
    QByteArray radareArchName = archFromFrida(archName).toUtf8();
    r_config_set(config, "asm.arch", radareArchName.data());
    r_config_set_i(config, "asm.bits", pointerSize * 8);
}

void RadareWorker::handleExecuteRequest(QString command, int requestId)
{
    auto commandStr = command.toUtf8();
    char *resultStr = r_core_cmd_str(m_core, commandStr.data());
    QString result;
    if (resultStr != nullptr) {
        result = resultStr;
        ::free(resultStr);
    }
    emit executeResponse(result, requestId);
}

static QString archFromFrida(QString name)
{
    if (name == "ia32" || name == "x64")
        return "x86";

    if (name == "arm64")
        return "arm";

    return name;
}
