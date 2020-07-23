import { Service } from "./interfaces";

export class ThreadMonitor implements Service {
    handlers = {};

    private threadTags = new Map<ThreadId, Set<ThreadTag>>();

    constructor() {
        this.emitThreads();
        this.monitorApis();
    }

    private emitThreads() {
        const entries: ThreadEntry[] = Process.enumerateThreads()
            .map(({ id }) => {
                return {
                    id,
                    tags: []
                };
            });
        send({
            name: "threads:update",
            payload: entries
        });
    }

    private monitorApis() {
        taggers().forEach(tagger => {
            const name = tagger.module[Process.platform];
            if (name === undefined) {
                return;
            }

            const mod = Process.findModuleByName(name);
            if (mod === null) {
                return;
            }

            const callbacks: InvocationListenerCallbacks = {};

            const { onEnter, onLeave } = tagger;
            const monitor = this;
            if (onEnter !== undefined) {
                callbacks.onEnter = function (args) {
                    monitor.tryCollectTag(onEnter.call(this, args), this);
                };
            }
            if (onLeave !== undefined) {
                callbacks.onLeave = function (retval) {
                    monitor.tryCollectTag(onLeave.call(this, retval), this);
                };
            }

            mod.enumerateExports()
                .filter(exp => exp.type === "function" && isApiFunction(exp.name))
                .forEach(exp => {
                    Interceptor.attach(exp.address, callbacks);
                });

            function isApiFunction(name: string) {
                return tagger.functions.some(prefix => name.indexOf(prefix) === 0);
            }
        });
    }

    private tryCollectTag(tag: ThreadTag | undefined, context: InvocationContext) {
        if (tag === undefined) {
            return;
        }

        const threadId = context.threadId;

        let tags = this.threadTags.get(threadId);
        if (tags === undefined) {
            tags = new Set();
            this.threadTags.set(threadId, tags);
        }

        if (!tags.has(tag)) {
            tags.add(tag);

            const entry: ThreadEntry = {
                id: threadId,
                tags: Array.from(tags)
            };
            send({
                name: "thread:update",
                payload: entry
            });
        }
    }
}

interface ThreadEntry {
    id: ThreadId;
    tags: ThreadTag[];
}

type ThreadTag =
    | "crypto"
    | "file"
    | "gui"
    | "ipc"
    | "net"
    ;

interface ThreadTagger {
    module: {
        [platformName: string]: ModuleName;
    };
    functions: FunctionPrefix[];
    onEnter?: TagOnEnterHandler;
    onLeave?: TagOnLeaveHandler;
}

type ModuleName = string;
type FunctionPrefix = string;
type TagOnEnterHandler = (this: InvocationContext, args: InvocationArguments) => ThreadTag | undefined;
type TagOnLeaveHandler = (this: InvocationContext, retval: InvocationReturnValue) => ThreadTag | undefined;

function taggers(): ThreadTagger[] {
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
            onEnter(args) {
                const fd = args[0].toInt32();
                switch (Socket.type(fd)) {
                    case "tcp":
                    case "udp":
                    case "tcp6":
                    case "udp6":
                        return "net";
                    case "unix:stream":
                    case "unix:dgram":
                        return "ipc";
                    default:
                        return "file";
                }
            }
        },
        {
            module: {
                "windows": "advapi32.dll"
            },
            functions: [
                "CryptEncrypt",
                "CryptDecrypt"
            ],
            onEnter() {
                return "crypto";
            }
        },
        {
            module: {
                "darwin": "libcommonCrypto.dylib"
            },
            functions: [
                "CCCryptor"
            ],
            onEnter() {
                return "crypto";
            }
        },
        {
            module: {
                "windows": "user32.dll"
            },
            functions: [
                "BeginPaint"
            ],
            onEnter() {
                return "gui";
            }
        },
        {
            module: {
                "darwin": "CoreGraphics"
            },
            functions: [
                "CGContextDrawImage"
            ],
            onEnter() {
                return "gui";
            }
        }
    ];
}
