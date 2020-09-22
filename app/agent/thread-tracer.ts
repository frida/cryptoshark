import { Service } from "./interfaces";
import { ModuleMonitor, ModuleLocation } from "./module-monitor";

export class ThreadTracer implements Service {
    handlers = {
        "thread:follow": this.follow,
        "thread:unfollow": this.unfollow,
        "function:add-probe": this.addProbe,
        "function:remove-probe": this.removeProbe,
        "function:update-probe": this.updateProbe
    };

    private probes = new Map<FunctionAddress, Probe>();

    constructor(private moduleMonitor: ModuleMonitor) {
    }

    follow(threadId: ThreadId) {
        const { moduleMonitor } = this;

        Stalker.follow(threadId, {
            events: {
                compile: true,
                call: true,
            },
            onCallSummary(summary) {
                moduleMonitor.synchronize();
                send({
                    name: "thread:summary",
                    payload: {
                        thread: {
                            id: threadId
                        },
                        summary: Object.entries(summary).map(([rawAddress, count]) => [moduleMonitor.resolve(ptr(rawAddress)), count])
                    }
                });
            },
            onReceive(rawEvents) {
                const blocks: Block[] = (Stalker.parse(rawEvents, { annotate: false, stringify: false }) as any)
                    .filter((e: StalkerCompileEventBare | StalkerCallEventBare) => e.length === 2)
                    .map(([start, end]: [NativePointer, NativePointer]): Block => [moduleMonitor.resolve(start), end.sub(start).toInt32()]);
                if (blocks.length !== 0) {
                    send({
                        name: "thread:coverage",
                        payload: {
                            thread: {
                                id: threadId
                            },
                            blocks
                        }
                    });
                }
            },
        });
    }

    unfollow(threadId: ThreadId) {
        Stalker.unfollow(threadId);
    }

    addProbe(handlerId: ProbeHandlerId, address: FunctionAddress, script: string) {
        let probe = this.probes.get(address);
        if (probe !== undefined) {
            throw new Error("Probe already exists");
        }

        const handler = parseHandler(script);

        const handlerHolder: ProbeHandlerHolder = [handler];
        const id = Stalker.addCallProbe(ptr(address), makeProbeCallback(handlerId, handlerHolder));
        probe = {
            id,
            handlerHolder
        };
        this.probes.set(address, probe);

        return probe.id;
    }

    removeProbe(address: FunctionAddress) {
        const probe = this.probes.get(address);
        if (probe === undefined) {
            throw new Error("No such probe");
        }

        Stalker.removeCallProbe(probe.id);

        this.probes.delete(address);
    }

    updateProbe(address: FunctionAddress, script: string) {
        const probe = this.probes.get(address);
        if (probe === undefined) {
            throw new Error("No such probe");
        }

        probe.handlerHolder[0] = parseHandler(script);
    }
};

export interface ThreadSummary {
    [address: string]: CallTarget;
}

export type Block = [ModuleLocation | NativePointer, number];

export interface CallTarget {
    symbol: ModuleSymbol | null;
    count: number;
}

export interface ModuleSymbol {
    module: ModuleName;
    offset: number;
}

export type ModuleName = string;

export type FunctionAddress = string;

interface Probe {
    id: ProbeId;
    handlerHolder: ProbeHandlerHolder;
}

type ProbeId = number;
type ProbeHandler = (args: InvocationArguments, log: LogHandler) => void;
type ProbeHandlerId = number;
type ProbeHandlerHolder = [ProbeHandler];

type LogHandler = (...message: string[]) => void;

function parseHandler(script: string): ProbeHandler {
    return new Function("args", "log", script) as ProbeHandler;
}

function makeProbeCallback(id: ProbeHandlerId, handlerHolder: ProbeHandlerHolder): StalkerScriptCallProbeCallback {
    function log() {
        send({
            name: "function:log",
            payload: {
                id: id,
                message: Array.prototype.slice.call(arguments).map(toString).join(", ")
            }
        });
    }

    function toString(arg: any) {
        return arg.toString();
    }

    return function (args) {
        handlerHolder[0](args, log);
    };
}
