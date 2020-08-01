import QtQuick 2.2
import QtQuick.Controls 1.2
import QtQuick.Controls.Styles 1.1

TextArea {
    function render(instructions) {
        var immediates = /((\b|-)(0x|[0-9])[0-9a-f]*)\b/g;
        var registers = /\b([re][abcd]x|[re][sd]i|[re][bs]p|[re]ip)\b/g;
        var lines = instructions.map(function (insn) {
            var line = "<font color=\"#ff8689\">" + _zeroPad(insn.address.substr(2)) + "</font>&nbsp;";
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
        var result = s;
        while (result.length < 8) {
            result = "0" + result;
        }
        return result;
    }

    style: TextAreaStyle {
        backgroundColor: "#060606"
    }
    font.family: fixedFont
    textFormat: TextEdit.RichText
    wrapMode: TextEdit.NoWrap
    readOnly: true
}
