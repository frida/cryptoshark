import { Service } from "./interfaces";
import { MemoryApi } from "./memory-api";
import { ModuleMonitor } from "./module-monitor";
import { ThreadMonitor } from "./thread-monitor";
import { ThreadTracer } from "./thread-tracer";

class Agent implements Service {
    exports: RpcExports = {};
    handlers = {
        "agent:symbolicate": this.symbolicate
    };

    private services: Service[] = [];

    constructor() {
        const moduleMonitor = new ModuleMonitor();

        this.services.push(
            new MemoryApi(),
            moduleMonitor,
            new ThreadMonitor(),
            new ThreadTracer(moduleMonitor),
        );

        this.exports.dispose = this.dispose.bind(this);
        for (const service of [this, ...this.services]) {
            for (const [name, handler] of Object.entries(service.handlers)) {
                this.exports[name] = handler.bind(service);
            }
        }

        const { platform, arch, pointerSize } = Process;
        send({
            name: "agent:ready",
            payload: {
                platform,
                arch,
                pointerSize
            }
        });
    }

    dispose() {
    }

    symbolicate(addresses: string[]): SymbolicateResult[] {
        return addresses
            .map(ptr)
            .map(DebugSymbol.fromAddress)
            .map(({ name }) => name ?? null);
    }
}

export type SymbolicateResult = string | null;

const agent = new Agent();
rpc.exports = agent.exports;
