import QtQuick 2.2
import QtQuick.Controls 1.2
import QtQuick.Dialogs 1.2

Dialog {
    property var models: null
    property string functionAddress: ""

    onFunctionAddressChanged: {
        script.text = models.functions.getByAddress(functionAddress).probe.script;
    }

    onAccepted: {
        models.functions.updateProbeScript(models.functions.getByAddress(functionAddress), script.text);
    }

    width: 564
    height: 350
    title: qsTr("Edit function:")
    modality: Qt.WindowModal
    standardButtons: AbstractDialog.Save | AbstractDialog.Cancel

    TextArea {
        id: script

        width: parent.width
        height: 290
        font.family: "Lucida Console"
        textFormat: TextEdit.PlainText
        wrapMode: TextEdit.NoWrap
    }
}
