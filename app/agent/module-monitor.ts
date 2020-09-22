import { Service } from "./interfaces";

export class ModuleMonitor implements Service {
    handlers = {
        "module:get-functions": this.getFunctions,
        "module:symbolicate": this.symbolicate
    };

    private current = new ModuleMap();
    private ids = new Map<ModuleKey, ModuleId>();
    private nextModuleId: ModuleId = 1;

    constructor() {
        this.processModules();
    }

    synchronize(): void {
        this.current.update();
        this.processModules();
    }

    private processModules(): void {
        const liveModules = this.current.values().reduce((result, plainModule, index) => {
            const { name, base, size, path } = plainModule;
            const key = keyFromModule(plainModule);
            const id = 0;
            const m: EnrichedModule = {
                id,
                name,
                base,
                size,
                path,
            };
            if (index === 0) {
                m.main = true;
            }
            return result.set(key, m);
        }, new Map<ModuleKey, EnrichedModule>());
        const currentIds = this.ids;

        const added = new Map<ModuleKey, EnrichedModule>();
        const removed = new Map<ModuleKey, ModuleId>();

        for (const [key, m] of liveModules.entries()) {
            if (!currentIds.has(key)) {
                added.set(key, m);
            }
        }
        for (const [key, id] of currentIds.entries()) {
            if (!liveModules.has(key)) {
                removed.set(key, id);
            }
        }

        for (const [key, m] of added.entries()) {
            const id = this.nextModuleId++;
            m.id = id;
            currentIds.set(key, id);
        }
        for (const key of removed.keys()) {
            currentIds.delete(key);
        }

        if (added.size > 0 || removed.size > 0) {
            send({
                name: "modules:update",
                payload: {
                    add: Array.from(added.values()),
                    remove: Array.from(removed.values())
                }
            });
        }
    }

    resolve(address: NativePointer): ModuleLocation | NativePointer {
        const m = this.current.find(address);
        if (m === null) {
            return address;
        }

        const id = this.ids.get(keyFromModule(m))!;
        return [id, address.sub(m.base).toInt32()];
    }

    getFunctions(name: string): ModuleFunction[] {
        const m = find(this.current.values(), m => m.name === name);
        if (m === undefined) {
            throw new Error(`Module “${name}” not in map`);
        }

        const { base } = m;
        return m.enumerateExports()
            .filter(e => e.type === "function")
            .map(e => [e.name, e.address.sub(base).toInt32()]);
    }

    symbolicate(module: string, offsets: number[]): SymbolicateResult[] {
        const m = find(this.current.values(), m => m.path === module);
        if (m === undefined) {
            throw new Error(`Module “${module}” not in map`);
        }

        const { base } = m;
        return offsets.map(offset => DebugSymbol.fromAddress(base.add(offset)).name);
    }
}

export type ModuleId = number;
export type ModuleLocation = [ModuleId, ModuleRelativeOffset];
export type ModuleFunction = [ModuleFunctionName, ModuleRelativeOffset];
export type ModuleFunctionName = string;
export type ModuleRelativeOffset = number;
export type SymbolicateResult = string | null;

export interface EnrichedModule {
    id: ModuleId,
    name: string;
    base: NativePointer;
    size: number;
    path: string;
    main?: boolean;
}

type ModuleKey = string;

function keyFromModule(m: Module): ModuleKey {
    return [m.name, m.base.toString()].join("-");
}

function find<T>(array: T[], predicate: (candidate: T) => boolean): T | undefined {
    for (const element of array) {
        if (predicate(element)) {
            return element;
        }
    }
}
