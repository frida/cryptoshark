sendThreads(function () {
    var apis = [
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
                var fd = args[0].toInt32();
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
    monitor(apis);
});

function sendThreads(callback) {
    var threads = [];
    Process.enumerateThreads({
        onMatch: function (thread) {
            threads.push({id: thread.id, tags: []});
        },
        onComplete: function () {
            send({name: 'threads:update', threads: threads});
            setTimeout(callback, 0);
        }
    });
}

function monitor(apis) {
    apis.forEach(function (api) {
        var moduleName = api.module[Process.platform];
        if (!moduleName) {
            return;
        }

        var callbacks = {};
        if (api.onEnter) {
            callbacks.onEnter = function (args) {
                invokeApiHandler.call(this, api.onEnter, args);
            };
        }
        if (api.onLeave) {
            callbacks.onLeave = function (retval) {
                invokeApiHandler.call(this, api.onLeave, retval);
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
    });
}

var threadTags = {};
function invokeApiHandler(handler, data) {
    var tag = handler(data);
    if (tag) {
        var threadId = this.threadId;
        var tags = threadTags[threadId];
        if (!tags) {
            tags = [];
            threadTags[threadId] = tags;
        }
        if (tags.indexOf(tag) === -1) {
            tags.push(tag);
            send({name: 'thread:update', thread: {id: threadId, tags: tags}});
        }
    }
}
