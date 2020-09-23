import QtQuick 2.2
import QtQuick.Controls 2.3

ScrollView {
    id: scrollView

    property var items: []
    property alias loading: indicator.visible
    property alias disassemblyFont: textArea.font
    signal navigationRequest(var type, var id)

    onItemsChanged: {
        const attributes = {
            none: "",
            pending: ` style="background-color: #f2a4a2"`,
            executed: ` style="background-color: #cdfdc6"`,
        };

        const lineBreak = "<br />";

        textArea.text = items.map(({ status, block, lines }, index) => {
                                      const prefix = (index > 0) ? lineBreak : "";
                                      return prefix + lines.map(_formatLine.bind(this, block, attributes[status])).join(lineBreak);
                                  }).join("\n");
    }

    function _formatLine(block, attributes, line, index) {
        if (index === 0 && block !== null) {
            const label = "#" + block;

            const needed = label.length - 2;
            let available = 0;
            while (available < needed) {
                if (line.startsWith("&nbsp;")) {
                    line = line.substr(6);
                } else if (line.startsWith("<font ")) {
                    line = line.replace(/^(<font.+?>)(.+?)(<\/font>)/, (_, openingTag, content, closingTag) => {
                                            if (content.length === 1)
                                                return "";
                                            return openingTag + content.substr(1) + closingTag;
                                        });
                } else {
                    line = line.substr(1);
                }
                available++;
            }

            return `<a href="block:${block}" style="background-color: #cdfdc6; text-decoration: none;">${label}</a>` + line;
        }

        return `<span${attributes}>&nbsp;</span>&nbsp;` + line;
    }

    TextArea {
        id: textArea

        background: Rectangle {
            color: "black"
        }
        palette.text: "#c7c7c7"
        textFormat: TextEdit.RichText
        wrapMode: TextEdit.NoWrap
        readOnly: true
        selectByKeyboard: true
        selectByMouse: true

        onLinkActivated: {
            const [type, id] = link.split(":");
            navigationRequest(type, id);
        }

        Text {
            id: indicator

            visible: false
            anchors.centerIn: parent
            text: "🥞"
            font.pointSize: 50

            SequentialAnimation on anchors.verticalCenterOffset {
                running: indicator.visible
                loops: Animation.Infinite
                NumberAnimation {
                    from: 0; to: 50
                    easing.type: Easing.InOutSine
                    duration: 500
                }
                NumberAnimation {
                    from: 50; to: 0
                    easing.type: Easing.InOutSine
                    duration: 500
                }
            }
        }
    }
}
