import QtQuick 2.2
import QtQuick.Controls 2.3

TextArea {
    function render(instructions) {
        const immediates = /((\b|-)(0x|[0-9])[0-9a-f]*)\b/g;
        const registers = /\b([re][abcd]x|[re][sd]i|[re][bs]p|[re]ip)\b/g;
        const lines = instructions.map(insn => {
            let line = "<font color=\"#ff8689\">" + _zeroPad(insn.address.substr(2)) + "</font>&nbsp;";
            line += "<font color=\"#6064f6\"><b>" + insn.mnemonic + "</b>";
            if (insn.opStr) {
                line += " " + insn.opStr
                    .replace(immediates, "<font color=\"#ffae6c\">$1</font>")
                    .replace(registers, "<font color=\"#dfde92\">$1</font>");
            }
            line += "</font>";
            return line;
        });
        text = lines.join("<br />");
    }

    function _zeroPad(s) {
        let result = s;
        while (result.length < 8) {
            result = "0" + result;
        }
        return result;
    }

    background: Rectangle {
        color: "#060606"
    }
    font: fixedFont
    textFormat: TextEdit.RichText
    wrapMode: TextEdit.NoWrap
    readOnly: true
    selectByKeyboard: true
    selectByMouse: true
}
