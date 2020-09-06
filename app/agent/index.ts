import { Service } from "./interfaces";
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
        );

        this.exports.dispose = this.dispose.bind(this);
        for (const service of this.services) {
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
}

const agent = new Agent();
rpc.exports = agent.exports;
