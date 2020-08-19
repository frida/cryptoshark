import QtQuick 2.0
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.1

Item {
    signal attach()
    signal spawn()

    ColumnLayout {
        anchors.centerIn: parent
        spacing: 10

        Label {
            text: qsTr("Not currently attached to any process.")
        }

        Button {
            text: qsTr("Attach")
            onClicked: attach()

            Layout.topMargin: 5
            Layout.alignment: Qt.AlignCenter
        }

        Button {
            text: qsTr("Spawn")
            onClicked: spawn()

            Layout.alignment: Qt.AlignCenter
        }
    }
}
