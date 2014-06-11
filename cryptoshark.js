var id = Math.floor(Math.random() * 0xffffffff);
send("Bonjour!");
setInterval(function () { console.log("Script[" + id + "] Tick!"); }, 1000);
