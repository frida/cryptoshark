import QtQuick 2.12
import QtQuick.Controls 2.13

TableView {
    id: tableView

    property int currentRow: -1
    property var columnTitles: []
    property var columnWidths: []
    signal activated(int row, int column)

    topMargin: 21
    ScrollBar.vertical: ScrollBar {}
    clip: true
    boundsBehavior: Flickable.StopAtBounds

    columnWidthProvider: function (column) {
        const width = columnWidths[column];
        if (width === -1) {
            return tableView.width - columnWidths.reduce((total, width) => total + Math.max(width, 0), 0);
        }
        return width;
    }

    Row {
        y: tableView.contentY
        z: 2
        Repeater {
            model: columnTitles.length
            Label {
                width: tableView.columnWidthProvider(modelData)
                height: 20
                padding: 5
                font.pixelSize: 10
                verticalAlignment: Text.AlignVCenter

                color: "#aaa"
                background: Rectangle { color: "#333" }

                text: columnTitles[modelData]
            }
        }
    }

    delegate: ItemDelegate {
        text: model.display
        highlighted: tableView.currentRow === row
        onClicked: tableView.currentRow = row
        onDoubleClicked: activated(row, column)
    }
}
