import QtQuick 2.2
import QtQuick.Controls 2.3

import "../app/ui/components"

ApplicationWindow {
    title: qsTr("DisassemblyViewTest")
    width: 1024
    height: 633

    DisassemblyView {
        id: view

        disassemblyFont.family: "Courier"

        Component.onCompleted: {
            const r = new XMLHttpRequest();
            r.onreadystatechange = () => {
                if (r.readyState === XMLHttpRequest.DONE) {
                    view.items = JSON.parse(r.responseText);
                }
            };
            r.open("GET", "./DisassemblyViewTest.json");
            r.send();
        }
    }
}
