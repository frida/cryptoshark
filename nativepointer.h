#ifndef NATIVEPOINTER_H
#define NATIVEPOINTER_H

#include <QObject>

class NativePointer : public QObject
{
    Q_OBJECT
public:
    explicit NativePointer(QObject *parent = 0);

    Q_INVOKABLE QString fromBaseAndOffset(QString base, int offset);

signals:

public slots:

};

#endif // NATIVEPOINTER_H
