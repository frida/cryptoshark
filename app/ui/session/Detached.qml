import QtQuick 2.0
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.1

Item {
    signal attach()
    signal spawn()

    ColumnLayout {
        anchors.centerIn: parent
        spacing: 10

        Image {
            source: Qt.resolvedUrl("../../images/logo.svg")
            sourceSize.width: 320

            Layout.bottomMargin: 30
            Layout.alignment: Qt.AlignCenter
        }

        Label {
            text: qsTr("Not currently attached to any process.")

            Layout.alignment: Qt.AlignCenter
            Layout.bottomMargin: 5
        }

        Button {
            text: qsTr("Attach")
            onClicked: attach()

            Layout.alignment: Qt.AlignCenter
        }

        Button {
            text: qsTr("Spawn")
            onClicked: spawn()

            Layout.alignment: Qt.AlignCenter
        }
    }
}
