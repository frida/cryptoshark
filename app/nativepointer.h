#ifndef NATIVEPOINTER_H
#define NATIVEPOINTER_H

#include <QObject>

class NativePointer : public QObject
{
    Q_OBJECT
    Q_DISABLE_COPY_MOVE(NativePointer)

public:
    explicit NativePointer(QObject *parent = 0);
    ~NativePointer();

    static NativePointer *instance();

    Q_INVOKABLE QString fromBaseAndOffset(QString base, int offset);

private:
    static NativePointer *s_instance;
};

#endif // NATIVEPOINTER_H
