#include "models.h"

#include <QCoreApplication>
#include <QDir>

Models *Models::s_instance = nullptr;

Models::Models(QObject *parent) :
    QObject(parent),
    m_modules(nullptr),
    m_functions(nullptr)
{
}

Models::~Models()
{
    s_instance = nullptr;
}

Models *Models::instance()
{
    if (s_instance == nullptr)
        s_instance = new Models();
    return s_instance;
}

void Models::open(QString name)
{
    if (m_db.isValid())
        Models::close();

    m_db = QSqlDatabase::addDatabase("QSQLITE");
    m_db.setDatabaseName(dbFilePath(name));
    m_db.open();
    m_db.exec("PRAGMA synchronous = OFF");
    m_db.exec("PRAGMA journal_mode = MEMORY");

    m_modules = new Modules(this, m_db);
    m_functions = new Functions(this, m_db);
    emit modulesChanged(m_modules);
    emit functionsChanged(m_functions);
}

void Models::close()
{
    if (!m_db.isValid())
        return;

    delete m_modules;
    delete m_functions;
    m_modules = nullptr;
    m_functions = nullptr;
    emit modulesChanged(m_modules);
    emit functionsChanged(m_functions);

    auto connectionName = m_db.connectionName();
    m_db = QSqlDatabase();
    QSqlDatabase::removeDatabase(connectionName);
}

QString Models::dbFilePath(QString name)
{
    QString fileName = name + ".db3"; // TODO: normalize
#if defined (Q_OS_WIN)
    return QCoreApplication::applicationDirPath() + QDir::separator() + fileName;
#elif defined (Q_OS_MAC)
    return QDir::homePath() + QDir::separator() + "Desktop" + QDir::separator() + fileName;
#else
    return QDir::homePath() + QDir::separator() + fileName;
#endif
}
