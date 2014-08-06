"use strict";

module.exports = ThreadMonitor;

function ThreadMonitor() {
    this.handlers = {};
    this._threadTags = {};
    Object.freeze(this);

    this._sendThreads()
    .then(this._monitorApis.bind(this));
}

ThreadMonitor.prototype._sendThreads = function () {
    return new Promise(function (resolve) {
        const threads = [];
        Process.enumerateThreads({
            onMatch: function (thread) {
                threads.push({id: thread.id, tags: []});
            },
            onComplete: function () {
                send({name: 'threads:update', payload: threads});
                resolve();
            }
        });
    });
};

ThreadMonitor.prototype._monitorApis = function () {
    apis().forEach(function (api) {
        const moduleName = api.module[Process.platform];
        if (!moduleName) {
            return;
        }

        const callbacks = {};
        const monitor = this;
        if (api.onEnter) {
            callbacks.onEnter = function (args) {
                monitor._invokeApiHandler(api.onEnter, args, this);
            };
        }
        if (api.onLeave) {
            callbacks.onLeave = function (retval) {
                monitor._invokeApiHandler(api.onLeave, retval, this);
            };
        }

        Module.enumerateExports(moduleName, {
            onMatch: function (exp) {
                if (exp.type === 'function' && isApiFunction(exp.name)) {
                    Interceptor.attach(exp.address, callbacks);
                }
            },
            onComplete: function () {
            }
        });

        function isApiFunction(name) {
            return api.functions.some(function (f) {
                return name.indexOf(f) === 0;
            });
        }
    }, this);
};

ThreadMonitor.prototype._invokeApiHandler = function (handler, data, context) {
    const tag = handler(data);
    if (tag) {
        const threadId = context.threadId;
        let tags = this._threadTags[threadId];
        if (!tags) {
            tags = [];
            this._threadTags[threadId] = tags;
        }
        if (tags.indexOf(tag) === -1) {
            tags.push(tag);
            send({name: 'thread:update', payload: {id: threadId, tags: tags}});
        }
    }
};

function apis() {
    return [
        {
            module: {
                "windows": "ws2_32.dll",
                "darwin": "libSystem.B.dylib",
                "linux": "libc-2.19.so"
            },
            functions: [
                "connect",
                "recv",
                "send",
                "read",
                "write"
            ],
            onEnter: function (args) {
                const fd = args[0].toInt32();
                switch (Socket.type(fd)) {
                    case 'tcp':
                    case 'udp':
                    case 'tcp6':
                    case 'udp6':
                        return 'net';
                    case 'unix:stream':
                    case 'unix:dgram':
                        return 'ipc';
                    default:
                        return 'file';
                }
            }
        },
        {
            module: {
                "darwin": "libcommonCrypto.dylib"
            },
            functions: [
                "CCCryptor"
            ],
            onEnter: function () {
                return 'crypto';
            }
        },
        {
            module: {
                "darwin": "CoreGraphics"
            },
            functions: [
                "CGContextDrawImage"
            ],
            onEnter: function () {
                return 'gui';
            }
        }
    ];
}
