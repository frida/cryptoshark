import QtQuick 2.0
import QtQuick.Controls 2.3

Item {
    signal attach()

    Column {
        anchors.centerIn: parent
        spacing: 10

        Label {
            id: message
            text: qsTr("Not currently attached to any process.")
        }

        Item {
            width: message.implicitWidth
            height: action.implicitHeight
            Button {
                id: action
                anchors.centerIn: parent
                text: qsTr("Attach")
                onClicked: {
                    attach();
                }
            }
        }
    }
}
