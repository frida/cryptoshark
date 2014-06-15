var id = Math.floor(Math.random() * 0xffffffff);

send("Bonjour!");
setInterval(function () { console.log("Script[" + id + "] Tick!"); }, 1000);

var onMessage = function (message) {
    console.log("Script[" + id + "]: " + JSON.stringify(message));
    send({ack: 'roger that'});
    recv(onMessage);
};
recv(onMessage);
