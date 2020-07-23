import { Service } from "./interfaces";

const unconditionalBranches = new Set([
    "jmp",
    "ret",
]);

export class Disassembler implements Service {
    handlers = {
        "function:disassemble": this.disassemble
    };

    disassemble(func: FunctionRef): Instruction[] {
        const result: Instruction[] = [];

        let address = ptr(func.address);
        do {
            const insn = Instruction.parse(address);
            if (insn === null) {
                break;
            }
            result.push(insn);

            if (unconditionalBranches.has(insn.mnemonic)) {
                break;
            }

            address = insn.next;
        } while (result.length < 100);

        return result;
    }
}

export interface FunctionRef {
    address: string;
}
