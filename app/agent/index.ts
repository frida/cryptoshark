import { Disassembler } from "./disassembler";
import { Service, RequestHandler } from "./interfaces";
import { ModuleMonitor } from "./module-monitor";
import { ThreadMonitor } from "./thread-monitor";
import { ThreadTracer } from "./thread-tracer";

class Agent {
    private services: Service[] = [];
    private stanzaHandlers = new Map<StanzaName, RequestHandler>();

    constructor() {
        const moduleMap = new ModuleMap();

        this.services.push(
            new ModuleMonitor(moduleMap),
            new ThreadMonitor(),
            new ThreadTracer(moduleMap),
            new Disassembler(),
        );

        for (const service of this.services) {
            for (const [name, handler] of Object.entries(service.handlers)) {
                this.stanzaHandlers.set(name, handler.bind(service));
            }
        }

        recv(this.onMessage);
    }

    dispose() {
    }

    private onMessage = (message: any) => {
        try {
            this.handleStanza(message);
        } finally {
            recv(this.onMessage);
        }
    }

    private handleStanza(stanza: Stanza) {
        const handler = this.stanzaHandlers.get(stanza.name);
        if (handler === undefined) {
            this.replyWithError(stanza, new Error(`Unknown stanza: ${stanza.name}`));
            return;
        }

        let value;
        try {
            value = handler(stanza.payload);
        } catch (e) {
            this.replyWithError(stanza, e);
            return;
        }

        if (value instanceof Promise) {
            value.then(result => {
                this.replyWithResult(stanza, result);
            }, error => {
                this.replyWithError(stanza, error);
            });
        } else {
            this.replyWithResult(stanza, value);
        }
    }

    private replyWithResult(stanza: Stanza, result: any) {
        send({
            id: stanza.id,
            name: "result",
            payload: result
        });
    }

    private replyWithError(stanza: Stanza, error: Error) {
        send({
            id: stanza.id,
            name: "error",
            payload: {
                message: error.message,
                stack: error.stack
            }
        });
    }
}

interface Stanza {
    id: StanzaId;
    name: StanzaName;
    payload: any;
}

type StanzaId = number;
type StanzaName = string;

const agent = new Agent();
rpc.exports = {
    dispose: agent.dispose.bind(agent),
};
