import QtQuick 2.0
import QtQuick.Controls 2.13
import QtQuick.Layouts 1.1

ListView {
    id: editor

    property string placeholder: ""

    function getVector() {
        const result = [];
        const n = strvModel.count;
        for (let i = 0; i !== n; i++) {
            result.push(strvModel.get(i).value);
        }
        return result;
    }

    function reset() {
        strvModel.clear();
        strvModel.append({ value: placeholder });
    }

    function _addOne() {
        const count = model.count;
        model.append({ value: (count === 0) ? placeholder : "" });
        currentIndex = count;
    }

    function _removeSelected() {
        model.remove(currentIndex);
    }

    function _update(index, value) {
        model.setProperty(index, 'value', value);
    }

    model: strvModel

    implicitWidth: Math.max(headerItem.implicitWidth, footerItem.implicitWidth)
    implicitHeight: contentHeight

    header: RowLayout {
        Button {
            text: qsTr("⇧")
            enabled: editor.currentItem !== null && editor.currentIndex !== 0
            onClicked: strvModel.move(editor.currentIndex, editor.currentIndex - 1, 1)
        }
        Button {
            text: qsTr("⇩")
            enabled: editor.currentItem !== null && editor.currentIndex !== strvModel.count - 1
            onClicked: strvModel.move(editor.currentIndex, editor.currentIndex + 1, 1)
        }
    }

    delegate: Item {
        id: frame

        property int margin: 2

        width: editor.headerItem.implicitWidth
        height: field.implicitHeight + margin

        onFocusChanged: {
            if (activeFocus) {
                field.forceActiveFocus();
            }
        }

        TextField {
            id: field

            x: frame.margin; y: frame.margin
            width: parent.width - 2 * frame.margin
            height: parent.height - 2 * frame.margin

            text: value
            selectByMouse: true

            onFocusChanged: {
                if (field.activeFocus) {
                    editor.currentIndex = index;
                }
            }

            onEditingFinished: editor._update(index, text);

            onAccepted: editor._addOne()

            Keys.onPressed: {
                if (event.key === Qt.Key_Backspace && field.text === "") {
                    editor._removeSelected();
                }
            }
        }
    }

    footer: RowLayout {
        Button {
            text: qsTr("+")
            onClicked: editor._addOne()
        }
        Button {
            text: qsTr("-")
            enabled: editor.currentItem !== null
            onClicked: editor._removeSelected()
        }
    }

    highlight: Rectangle {
        property int size: 3

        width: (editor.currentItem !== null) ? editor.currentItem.width + 2 * size : 0
        height: (editor.currentItem !== null) ? editor.currentItem.height + 2 * size : 0
        color: "lightsteelblue"; radius: 5

        x: (editor.currentItem !== null) ? editor.currentItem.x - size : 0
        y: (editor.currentItem !== null) ? editor.currentItem.y - size : 0
        Behavior on y {
            SpringAnimation {
                spring: 3
                damping: 0.2
            }
        }
    }
    highlightFollowsCurrentItem: false
    focus: true

    onCurrentItemChanged: {
        if (currentItem !== null) {
            currentItem.forceActiveFocus();
        }
    }

    ListModel {
        id: strvModel
    }
}
