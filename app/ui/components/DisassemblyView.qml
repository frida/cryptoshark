import QtQuick 2.2
import QtQuick.Controls 2.3

ScrollView {
    id: scrollView

    property alias text: textArea.text
    property alias loading: indicator.visible

    TextArea {
        id: textArea

        background: Rectangle {
            color: "black"
        }
        palette.text: "#c7c7c7"
        font: fixedFont
        textFormat: TextEdit.RichText
        wrapMode: TextEdit.NoWrap
        readOnly: true
        selectByKeyboard: true
        selectByMouse: true

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
