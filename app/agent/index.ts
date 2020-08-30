import { Disassembler } from "./disassembler";
import { Service, RequestHandler } from "./interfaces";
import { MemoryApi } from "./memory-api";
import { ModuleMonitor } from "./module-monitor";
import { ThreadMonitor } from "./thread-monitor";
import { ThreadTracer } from "./thread-tracer";

class Agent {
    exports: RpcExports = {};

    private services: Service[] = [];

    constructor() {
        const moduleMap = new ModuleMap();

        this.services.push(
            new MemoryApi(),
            new ModuleMonitor(moduleMap),
            new ThreadMonitor(),
            new ThreadTracer(moduleMap),
            new Disassembler(),
        );

        this.exports.dispose = this.dispose.bind(this);
        for (const service of this.services) {
            for (const [name, handler] of Object.entries(service.handlers)) {
                this.exports[name] = handler.bind(service);
            }
        }
    }

    dispose() {
    }
}

const agent = new Agent();
rpc.exports = agent.exports;
