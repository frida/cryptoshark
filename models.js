var modules = new Modules();
var functions = new Functions(modules);

function open(process, callback) {
    var database = LocalStorage.openDatabaseSync(process.name, "1.0", "CryptoShark Database", 1000000);
    database.transaction(function (tx) {
        tx.executeSql("CREATE TABLE IF NOT EXISTS modules (" +
            "id INTEGER PRIMARY KEY, " +
            "name TEXT NOT NULL UNIQUE, " +
            "path TEXT NOT NULL UNIQUE, " +
            "base INTEGER NOT NULL, " +
            "calls INTEGER NOT NULL DEFAULT 0" +
        ")");
        tx.executeSql("CREATE INDEX IF NOT EXISTS modules_index ON modules(name, path);");

        tx.executeSql("CREATE TABLE IF NOT EXISTS functions (" +
            "id INTEGER PRIMARY KEY, " +
            "name TEXT NOT NULL UNIQUE, " +
            "module INTEGER, " +
            "offset INTEGER NOT NULL, " +
            "calls INTEGER NOT NULL DEFAULT 0, " +
            "FOREIGN KEY(module) REFERENCES modules(id)" +
        ")");

        modules.database = database;
        functions.database = database;

        callback();
    });
}

function close() {
    functions.database = null;
    modules.database = null;
}

function Modules() {
    var database = null;
    var cache = {};
    var listeners = [];

    Object.defineProperty(this, 'database', {
        get: function () {
            return database;
        },
        set: function (value) {
            database = value;
            cache = {};
            onChange();
        }
    });

    this._getByName = function (name, transaction) {
        var module = cache[name];
        if (module) {
            return module;
        }
        module = transaction.executeSql("SELECT * FROM modules WHERE name = ?", [name]).rows[0];
        cache[name] = module;
        return module;
    };

    this.allWithCalls = function (callback) {
        if (database === null) {
            callback([]);
            return;
        }

        database.transaction(function (tx) {
            var rows = tx.executeSql("SELECT * FROM modules WHERE calls > 0 ORDER BY calls DESC").rows;
            callback(Array.prototype.slice.call(rows));
        });
    };

    this.update = function (update) {
        database.transaction(function (tx) {
            update.forEach(function (mod) {
                if (tx.executeSql("SELECT 1 FROM modules WHERE name = ?", [mod.name]).rows.length === 0) {
                    tx.executeSql("INSERT INTO modules (name, path, base) VALUES (?, ?, ?)", [mod.name, mod.path, mod.base]);
                } else {
                    tx.executeSql("UPDATE modules SET path = ?, base = ? WHERE name = ?", [mod.path, mod.base, mod.name]);
                }
            });
            cache = {};
            onChange();
        });
    };

    this.incrementCalls = function (updates) {
        database.transaction(function (tx) {
            for (var id in updates) {
                if (updates.hasOwnProperty(id)) {
                    var calls = updates[id];
                    tx.executeSql("UPDATE modules SET calls = calls + ? WHERE id = ?", [calls, id]);
                }
            }
            cache = {};
            onChange();
        });
    };

    this.listen = function (callback) {
        listeners.push(callback);
        callback();
    };

    function onChange() {
        listeners.forEach(function (notify) {
            notify();
        });
    }

    Object.freeze(this);
}

function Functions(modules) {
    var database = null;
    var listeners = [];

    Object.defineProperty(this, 'database', {
        get: function () {
            return database;
        },
        set: function (value) {
            database = value;
            onChange();
        }
    });

    this.findByModule = function (moduleId, callback) {
        if (database === null) {
            callback([]);
            return;
        }

        database.transaction(function (tx) {
            var rows = tx.executeSql("SELECT * FROM functions WHERE module = ? ORDER BY calls DESC", [moduleId]).rows;
            callback(Array.prototype.slice.call(rows));
        });
    };

    this.update = function (update) {
        database.transaction(function (tx) {
            var summary = update.summary;
            var moduleCalls = {};
            for (var address in summary) {
                if (summary.hasOwnProperty(address)) {
                    var entry = summary[address];
                    var symbol = entry.symbol;
                    if (symbol) {
                        var module = modules._getByName(symbol.module, tx);
                        var result = tx.executeSql("UPDATE functions SET calls = calls + ? WHERE module = ? AND offset = ?", [entry.count, module.id, symbol.offset]);
                        if (result.rowsAffected === 0) {
                            var name = symbol.module + "+0x" + symbol.offset.toString(16);
                            tx.executeSql("INSERT INTO functions (name, module, offset, calls) VALUES (?, ?, ?, ?)", [name, module.id, symbol.offset, entry.count]);
                        }
                        moduleCalls[module.id] = (moduleCalls[module.id] || 0) + entry.count;
                    } else {
                        // TODO
                    }
                }
            }
            modules.incrementCalls(moduleCalls);
            onChange();
        });
    };

    this.listen = function (callback) {
        listeners.push(callback);
        callback();
    };

    function onChange() {
        listeners.forEach(function (notify) {
            notify();
        });
    }

    Object.freeze(this);
};
