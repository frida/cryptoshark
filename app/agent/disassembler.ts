import { Service } from "./interfaces";

const unconditionalBranches = new Set([
    "jmp",
    "ret",
]);

export class Disassembler implements Service {
    handlers = {
        "function:disassemble": this.disassemble
    };

    disassemble(rawAddress: string): Instruction[] {
        const result: Instruction[] = [];

        let address = ptr(rawAddress);
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
