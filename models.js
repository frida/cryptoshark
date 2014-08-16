.import QtQuick.LocalStorage 2.0 as QLS
.import "vendor.js" as Vendor

var scheduler = new IOScheduler();
var modules = new Modules();
var functions = new Functions(modules, scheduler);

function open(process, callback) {
    var database = QLS.LocalStorage.openDatabaseSync(process.name, "1.0", "CryptoShark Database", 1000000);
    database.transaction(function (tx) {
        tx.executeSql("CREATE TABLE IF NOT EXISTS modules (" +
            "id INTEGER PRIMARY KEY, " +
            "name TEXT NOT NULL UNIQUE, " +
            "path TEXT NOT NULL UNIQUE, " +
            "base INTEGER NOT NULL, " +
            "main INTEGER NOT NULL, " +
            "calls INTEGER NOT NULL DEFAULT 0" +
        ")");
        tx.executeSql("CREATE INDEX IF NOT EXISTS modules_index ON modules(name, path, calls);");

        tx.executeSql("CREATE TABLE IF NOT EXISTS functions (" +
            "id INTEGER PRIMARY KEY, " +
            "name TEXT NOT NULL UNIQUE, " +
            "module INTEGER, " +
            "offset INTEGER NOT NULL, " +
            "exported INTEGER NOT NULL DEFAULT 0, " +
            "calls INTEGER NOT NULL DEFAULT 0, " +
            "probe_script TEXT, " +
            "FOREIGN KEY(module) REFERENCES modules(id)" +
        ")");
        tx.executeSql("CREATE INDEX IF NOT EXISTS functions_index ON functions(module, calls, exported);");

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
    var metadataProvider = null;
    var cache = {};

    function AllWithCalls() {
        var items = [];
        var observers = [];

        var observable = {
            addObserver: function (observer) {
                observers.push(observer);
                observer.onModulesUpdate(items);
            },
            removeObserver: function (observer) {
                observers.splice(observers.indexOf(observer), 1);
            }
        };
        Object.defineProperty(observable, 'items', {get: function () { return items; }});
        Object.freeze(observable);

        this.observable = observable;

        this.load = function (database) {
            database.transaction(function (tx) {
                var rows = tx.executeSql("SELECT * FROM modules WHERE calls > 0 ORDER BY calls DESC").rows;
                items = Array.prototype.slice.call(rows);
                notifyObservers('onModulesUpdate', items);
            });
        };

        this.unload = function () {
            items = [];
            notifyObservers('onModulesUpdate', items);
        };

        function notifyObservers(event) {
            var args = Array.prototype.slice.call(arguments, 1);
            observers.forEach(function (observer) {
                if (observer[event]) {
                    observer[event].apply(observer, args);
                }
            });
        }

        Object.freeze(this);
    };

    var allWithCalls = new AllWithCalls();

    this.allWithCalls = function () {
        return allWithCalls.observable;
    };

    Object.defineProperty(this, 'database', {
        get: function () {
            return database;
        },
        set: function (value) {
            database = value;
            cache = {};
            if (database) {
                allWithCalls.load(database);
            } else {
                allWithCalls.unload();
            }
        }
    });

    Object.defineProperty(this, 'metadataProvider', {
        get: function () {
            return metadataProvider;
        },
        set: function (value) {
            metadataProvider = value;
        }
    });

    this.update = function (update) {
        database.transaction(function (tx) {
            update.forEach(function (mod) {
                if (tx.executeSql("SELECT 1 FROM modules WHERE name = ?", [mod.name]).rows.length === 0) {
                    tx.executeSql("INSERT INTO modules (name, path, base, main) VALUES (?, ?, ?, ?)", [mod.name, mod.path, mod.base, mod.main ? 1 : 0]);
                } else {
                    tx.executeSql("UPDATE modules SET path = ?, base = ? WHERE name = ?", [mod.path, mod.base, mod.name]);
                }
            });
            cache = {};

            allWithCalls.load(database);
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

            allWithCalls.load(database);
        });
    };

    this._getByName = function (name, transaction) {
        var module = cache[name];
        if (module) {
            return module;
        }
        module = transaction.executeSql("SELECT * FROM modules WHERE name = ?", [name]).rows[0];
        cache[name] = module;
        return module;
    };

    Object.freeze(this);
}

function Functions(modules, scheduler) {
    var database = null;
    var collections = {};
    var functionByName = {};
    var functionByAddress = {};
    var logHandlers = [];

    function Collection(module) {
        var items = [];
        var functionByOffset = {};
        var dirty = {};
        var exportsScanned = false;
        var observers = [];

        var observable = {
            addObserver: function (observer) {
                observers.push(observer);
                observer.onFunctionsUpdate(items);
            },
            removeObserver: function (observer) {
                observers.splice(observers.indexOf(observer), 1);
            }
        };
        Object.defineProperty(observable, 'items', {get: function () { return items; }});
        Object.freeze(observable);

        this.observable = observable;

        this.load = function (database) {
            database.transaction(function (tx) {
                var rows = tx.executeSql("SELECT * FROM functions WHERE module = ? ORDER BY calls DESC", [module.id]).rows;
                var allItems = Array.prototype.map.call(rows, loadFunction);
                items = allItems.filter(function (item) {
                    return item.calls > 0;
                });
                allItems.forEach(function (func) {
                    functionByName[func.name] = func;
                    functionByAddress[func.address] = func;
                });
                functionByOffset = allItems.reduce(function (functions, func) {
                    functions[func.offset] = func;
                    return functions;
                }, {});
                notifyObservers('onFunctionsUpdate', items);
            });
        };

        this.unload = function () {
            items = [];
            functionByOffset = {};
            dirty = {};
            exportsScanned = false;
            notifyObservers('onFunctionsUpdate', items);
        };

        this.update = function (updates) {
            var updated = [];

            updates.forEach(function (update) {
                var offset = update[0];
                var calls = update[1];

                var func = functionByOffset[offset];
                if (func) {
                    func.calls += calls;
                } else {
                    func = createFunction(functionName(module, offset), offset, calls);
                    functionByName[func.name] = func;
                    functionByAddress[func.address] = func;
                    functionByOffset[offset] = func;
                }
                updated.push(func);

                dirty[func.name] = func;
            });

            updated.forEach(function (func) {
                var oldIndex = items.indexOf(func);
                if (oldIndex === -1) {
                    var index = sortedIndexOf(func);
                    items.splice(index, 0, func);
                    notifyObservers('onFunctionsAdd', index, func);
                } else {
                    items.splice(oldIndex, 1);
                    var newIndex = sortedIndexOf(func);
                    if (newIndex !== oldIndex) {
                        items.splice(newIndex, 0, func);
                        notifyObservers('onFunctionsMove', oldIndex, newIndex);
                        notifyObservers('onFunctionsUpdate', items, [newIndex, 'calls', func.calls]);
                    } else {
                        items.splice(oldIndex, 0, func);
                        notifyObservers('onFunctionsUpdate', items, [oldIndex, 'calls', func.calls]);
                    }
                }
            });

            scheduler.schedule(flush);
        };

        this.updateProbeId = function (func, id) {
            func = functionByOffset[func.offset];
            func.probe.id = id;
            var index = items.indexOf(func);
            notifyObservers('onFunctionsUpdate', items, [index, 'probe', func.probe]);
        };

        function createFunction(name, offset, calls) {
            return {
                name: name,
                address: bigInt(module.base).add(bigInt(offset)).toString(),
                module: module.id,
                offset: offset,
                exported: false,
                calls: calls,
                probe: {
                    id: -1,
                    script: ""
                }
            };
        }

        function loadFunction(data) {
            return {
                id: data.id,
                name: data.name,
                address: bigInt(module.base).add(bigInt(data.offset)).toString(),
                module: data.module,
                offset: data.offset,
                exported: data.exported,
                calls: data.calls,
                probe: {
                    id: -1,
                    script: data.probe_script || ""
                }
            };
        }

        function bigInt(value) {
            if (typeof value === 'string' && value.indexOf("0x") === 0) {
                return Vendor.bigInt(value.substr(2), 16);
            } else {
                return Vendor.bigInt(value);
            }
        }

        function functionName(module, offset) {
            return functionPrefix(module) + "_" + offset.toString(16);
        }

        function functionPrefix(module) {
            if (module.main) {
                return "sub";
            } else {
                return module.name.replace(/^lib/, "").replace(/[-_]/g, "").replace(/\.\w+$/, "").toLocaleLowerCase();
            }
        }

        function flush(quotaExceeded) {
            if (!exportsScanned) {
                exportsScanned = true;
                scanExports();
            }

            var finished = true;
            do {
                database.transaction(function (tx) {
                    var finishedNames = [];
                    for (var name in dirty) {
                        if (dirty.hasOwnProperty(name)) {
                            var func = dirty[name];
                            if (func.id) {
                                tx.executeSql("UPDATE functions SET name = ?, exported = ?, calls = ?, probe_script = ? WHERE id = ?", [func.name, func.exported, func.calls, func.probe.script || null, func.id]);
                            } else {
                                var result = tx.executeSql("INSERT INTO functions (name, module, offset, exported, calls, probe_script) VALUES (?, ?, ?, ?, ?, ?)", [name, module.id, func.offset, func.exported, func.calls, func.probe.script || null]);
                                func.id = result.insertId;
                            }
                            finishedNames.push(name);
                            if (finishedNames.length === 10) {
                                finished = false;
                                break;
                            }
                        }
                    }
                    finishedNames.forEach(function (name) {
                        delete dirty[name];
                    });
                });
            }
            while (!finished && !quotaExceeded());

            return finished;
        }

        function scanExports() {
            database.transaction(function (tx) {
                if (tx.executeSql("SELECT 1 FROM functions WHERE module = ? AND exported = 1", [module.id]).rows.length === 0) {
                    modules.metadataProvider.getModuleFunctions(module.name, function (moduleFuncs) {
                        moduleFuncs.forEach(function (moduleFunc) {
                            var name = moduleFunc[0];
                            if (functionByName[name]) {
                                name = functionPrefix(module) + "_" + name;
                            }
                            var offset = moduleFunc[1];

                            var func = functionByOffset[offset];
                            if (func) {
                                delete functionByName[func.name];
                                functionByName[name] = func;
                                delete dirty[func.name];
                                func.name = name;
                                func.exported = true;
                            } else {
                                func = createFunction(name, offset, 0);
                                functionByName[name] = func;
                                functionByAddress[func.address] = func;
                                functionByOffset[offset] = func;
                            }

                            if (func.calls > 0) {
                                var index = items.indexOf(func);
                                notifyObservers('onFunctionsUpdate', items, [index, 'name', name]);
                                notifyObservers('onFunctionsUpdate', items, [index, 'exported', true]);
                            }

                            dirty[name] = func;
                        });
                        scheduler.schedule(flush);
                    });
                }
            });
        }

        function sortedIndexOf(func) {
            for (var i = 0; i !== items.length; i++) {
                if (func.calls > items[i].calls) {
                    return i;
                }
            }
            return items.length;
        }

        function notifyObservers(event) {
            var args = Array.prototype.slice.call(arguments, 1);
            observers.forEach(function (observer) {
                if (observer[event]) {
                    observer[event].apply(observer, args);
                }
            });
        }

        Object.freeze(this);
    };

    function getCollection(module) {
        var collection = collections[module.id];
        if (!collection) {
            collection = new Collection(module);
            if (database) {
                collection.load(database);
            }
            collections[module.id] = collection;
        }
        return collection;
    }

    this.allInModule = function (module) {
        return getCollection(module).observable;
    };

    this.updateProbeId = function (func, id) {
        collections[func.module].updateProbeId(func, id);
    };

    Object.defineProperty(this, 'database', {
        get: function () {
            return database;
        },
        set: function (value) {
            database = value;

            for (var moduleId in collections) {
                if (collections.hasOwnProperty(moduleId)) {
                    if (database) {
                        collections[moduleId].load(database);
                    } else {
                        collections[moduleId].unload();
                    }
                }
            }
        }
    });

    this.update = function (update) {
        database.transaction(function (tx) {
            var updates;

            var summary = update.summary;
            var collectionUpdates = {};
            var moduleCalls = {};
            for (var address in summary) {
                if (summary.hasOwnProperty(address)) {
                    var entry = summary[address];
                    var symbol = entry.symbol;
                    if (symbol) {
                        var module = modules._getByName(symbol.module, tx);
                        updates = collectionUpdates[module.id];
                        if (!updates) {
                            updates = [getCollection(module)];
                            collectionUpdates[module.id] = updates;
                        }
                        updates.push([symbol.offset, entry.count]);
                        moduleCalls[module.id] = (moduleCalls[module.id] || 0) + entry.count;
                    } else {
                        // TODO
                    }
                }
            }

            for (var moduleId in collectionUpdates) {
                if (collectionUpdates.hasOwnProperty(moduleId)) {
                    updates = collectionUpdates[moduleId];
                    var collection = updates[0];
                    collection.update(updates.slice(1));
                }
            }

            modules.incrementCalls(moduleCalls);
        });
    };

    this.log = function (entry) {
        var func = functionByAddress[entry.address];
        var message = entry.message;
        logHandlers.forEach(function (handler) {
            handler(func, message);
        });
    };

    this.addLogHandler = function (handler) {
        logHandlers.push(handler);
    };

    this.removeLogHandler = function (handler) {
        logHandlers.splice(logHandlers.indexOf(handler), 1);
    };

    Object.freeze(this);
};

function IOScheduler() {
    var timer = null;
    var pending = [];

    this.configure = function (t) {
        timer = t;
        timer.interval = 15;
        timer.repeat = true;
    };

    this.tick = function () {
        var started = new Date();

        function quotaExceeded() {
            var now = new Date();
            var elapsed = now - started;
            return elapsed >= 10;
        }

        while (pending.length > 0) {
            var work = pending[0];
            var finished = work(quotaExceeded);
            if (finished) {
                pending.splice(0, 1);
            } else {
                break;
            }
        }

        if (pending.length === 0) {
            timer.stop();
        }
    };

    this.schedule = function (work) {
        pending.push(work);
        timer.start();
    };
}
