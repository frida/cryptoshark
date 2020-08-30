import { Service } from "./interfaces";

const { pageSize } = Process;

export class MemoryApi implements Service {
    handlers = {
        "memory:read": this.read
    };

    read(rawAddress: string, count: number): ArrayBuffer {
        const address = ptr(rawAddress);
        if (address.compare(pageSize) === -1) {
            throw new Error("Invalid address");
        }

        try {
            return address.readByteArray(count)!;
        } catch (e) {
            throw new Error("Invalid address");
        }
    }
}
