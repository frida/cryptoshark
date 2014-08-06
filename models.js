var database = null;

function load(process, callback) {
    database = LocalStorage.openDatabaseSync("cryptoshark-" + process.name, "1.0", "CryptoShark data for " + process.name, 1000000);
    database.transaction(function (tx) {
        callback();
    });
}
