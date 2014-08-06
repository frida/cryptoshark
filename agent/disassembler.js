"use strict";

module.exports = Disassembler;

function Disassembler() {
    this.handlers = {
        'function:disassemble': this.disassemble
    };
    Object.freeze(this);
}

const unconditionalBranches = {
    'jmp': true,
    'ret': true
};
Object.freeze(unconditionalBranches);

Disassembler.prototype.disassemble = function (func) {
    return new Promise(function (resolve) {
        const result = [];

        let address = ptr(func.address);
        while (result.length < 100) {
            const insn = Instruction.parse(address);
            if (insn === null) {
                break;
            }
            result.push(insn);

            if (unconditionalBranches[insn.mnemonic]) {
                break;
            }

            address = insn.next;
        }

        resolve(result);
    });
};
