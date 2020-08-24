import QtQuick 2.12
import QtQuick.Controls 2.13 as Controls
import QtQuick.Layouts 1.1
import Qt.labs.platform 1.1 as Labs
import Frida 1.0

Controls.Dialog {
    id: dialog

    property var currentDevice: (devices.currentIndex !== -1) ? deviceModel.get(devices.currentIndex) : null

    signal selected(var device, string program, var options)

    onOpened: {
        if (applicationsModel.count !== 0) {
            applicationsModel.refresh();
        }
    }

    onAccepted: {
        const device = currentDevice;
        if (device === null)
            return;

        const program = programField.text;
        if (program === "")
            return;

        if (customArgvButton.checked) {
            spawnOptions.argv = argvEditor.getVector();
        } else {
            spawnOptions.unsetArgv();
        }

        if (customEnvButton.checked) {
            spawnOptions.env = envEditor.getVector();
        } else {
            spawnOptions.unsetEnv();
        }

        if (customCwdButton.checked) {
            spawnOptions.cwd = cwdField.text;
        } else {
            spawnOptions.unsetCwd();
        }

        selected(device, program, spawnOptions);
    }

    onCurrentDeviceChanged: {
        applications.currentIndex = -1;

        programField.text = "";

        [defaultArgvButton, defaultEnvButton, defaultCwdButton].forEach(radioButton => {
            if (!radioButton.checked)
                radioButton.toggle();
        });
    }

    width: parent.width - 50
    height: parent.height - 20
    anchors.centerIn: parent

    title: qsTr("Choose program to spawn:")
    modal: true
    standardButtons: Controls.Dialog.Ok | Controls.Dialog.Cancel

    Controls.SplitView {
        anchors.fill: parent

        ListView {
            id: devices

            model: deviceModel

            Controls.SplitView.minimumWidth: 50
            Controls.SplitView.preferredWidth: 150
            boundsBehavior: Flickable.StopAtBounds

            delegate: Controls.ItemDelegate {
                text: name
                icon.source: model.icon
                width: (parent !== null) ? parent.width : 50
                highlighted: ListView.isCurrentItem
                onClicked: devices.currentIndex = index
            }
        }

        ListView {
            id: applications

            model: applicationsModel

            visible: model.count > 0
            Controls.SplitView.minimumWidth: 50
            Controls.SplitView.preferredWidth: 150
            boundsBehavior: Flickable.StopAtBounds

            delegate: Controls.ItemDelegate {
                text: name
                icon.source: smallIcon
                width: (parent !== null) ? parent.width : 50
                highlighted: ListView.isCurrentItem
                onClicked: applications.currentIndex = index
                onDoubleClicked: dialog.accept()
            }

            onCurrentIndexChanged: {
                const application = model.get(currentIndex);
                if (application !== null) {
                    programField.text = application.identifier;
                }
            }
        }

        Flickable {
            contentWidth: options.width
            contentHeight: options.height
            Controls.SplitView.minimumWidth: 50
            Controls.SplitView.preferredWidth: 350

            Controls.ScrollBar.vertical: Controls.ScrollBar {}
            clip: true
            boundsBehavior: Flickable.StopAtBounds

            Column {
                id: options

                leftPadding: 10
                spacing: 10

                Controls.GroupBox {
                    id: program
                    title: qsTr("Program")
                    Controls.TextField {
                        id: programField
                        implicitWidth: 230
                        placeholderText: (currentDevice === null || currentDevice.type === Device.Type.Local)
                            ? Cryptoshark.exampleLocalProgram
                            : Cryptoshark.exampleRemoteProgram
                        selectByMouse: true
                    }
                }

                Controls.GroupBox {
                    id: argv
                    title: qsTr("Argument Vector")
                    Column {
                        Controls.RadioButton {
                            id: defaultArgvButton
                            text: qsTr("Default")
                            checked: true
                        }
                        Controls.RadioButton {
                            id: customArgvButton
                            text: qsTr("Custom")
                            onToggled: argvEditor.reset()
                        }
                        StringVectorEditor {
                            id: argvEditor
                            visible: customArgvButton.checked
                            placeholder: programField.text
                        }
                    }
                }

                Controls.GroupBox {
                    id: env
                    title: qsTr("Environment")
                    Column {
                        Controls.RadioButton {
                            id: defaultEnvButton
                            text: qsTr("Default")
                            checked: true
                        }
                        Controls.RadioButton {
                            id: customEnvButton
                            text: qsTr("Custom")
                            onToggled: envEditor.reset()
                        }
                        StringVectorEditor {
                            id: envEditor
                            visible: customEnvButton.checked
                            placeholder: "CLICOLOR=1"
                        }
                    }
                }

                Controls.GroupBox {
                    id: cwd
                    title: qsTr("Working Directory")
                    Column {
                        Controls.RadioButton {
                            id: defaultCwdButton
                            text: qsTr("Default")
                            checked: true
                        }
                        Controls.RadioButton {
                            id: customCwdButton
                            text: qsTr("Custom")
                            onToggled: cwdField.text = "/"
                        }
                        Controls.TextField {
                            id: cwdField
                            visible: customCwdButton.checked
                            selectByMouse: true
                        }
                    }
                }

            }
        }
    }

    SpawnOptions {
        id: spawnOptions
    }

    DeviceListModel {
        id: deviceModel
    }

    ApplicationListModel {
        id: applicationsModel
        device: currentDevice

        onError: {
            errorDialog.text = message;
            errorDialog.open();
        }
    }

    Labs.MessageDialog {
        id: errorDialog
    }
}
