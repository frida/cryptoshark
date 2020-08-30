import { Service } from "./interfaces";

export class ThreadTracer implements Service {
    handlers = {
        "thread:follow": this.follow,
        "thread:unfollow": this.unfollow,
        "function:add-probe": this.addProbe,
        "function:remove-probe": this.removeProbe,
        "function:update-probe": this.updateProbe
    };

    private probes = new Map<FunctionAddress, Probe>();

    constructor(private moduleMap: ModuleMap) {
    }

    follow(threadId: ThreadId) {
        const moduleMap = this.moduleMap;

        Stalker.follow(threadId, {
            events: {
                call: true
            },
            onCallSummary(summary) {
                const enrichedSummary: ThreadSummary = {};
                for (const [rawAddress, count] of Object.entries(summary)) {
                    const address = ptr(rawAddress);

                    let symbol: ModuleSymbol | null = null;
                    const m = moduleMap.find(address);
                    if (m !== null) {
                        symbol = {
                            module: m.name,
                            offset: address.sub(m.base).toInt32()
                        };
                    }

                    enrichedSummary[rawAddress] = {
                        symbol,
                        count
                    };
                }

                send({
                    name: "thread:summary",
                    payload: {
                        thread: {
                            id: threadId
                        },
                        summary: enrichedSummary
                    }
                });
            }
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
