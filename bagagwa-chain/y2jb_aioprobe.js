// y2jb_aioprobe.js -- find WORKING aio_init args on 13.40, one combo at a time.
// Send: python payload_sender.py <PS5-IP> <PORT> y2jb_aioprobe.js
// Needs y2jb_logserver.py running. Narrates via popups (TV alone suffices).
// aio_init(0,0) returns -1 here, so we try the arg matrix; the first combo
// returning 0 is immediately followed by aio_create(0). No state persists
// except a successfully-initialized AIO subsystem (which bagagwa wants anyway).
(async () => {
    const LOG_HOST = "192.168.0.163"; // <-- your Mac IP
    const say = (s) => { try { log("[aio] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    let net = "OFF";
    try { net = (typeof NETWORK_LOGGING !== "undefined" && NETWORK_LOGGING) ? "ON" : "OFF"; } catch (e) {}

    shout("aio: start net=" + net);
    say("aioprobe start");

    const combos = [[0, 0], [1, 0], [0, 1], [1, 1]];
    for (const pair of combos) {
        const a = pair[0], b = pair[1];
        try {
            const r = await syscall(0x29En, BigInt(a), BigInt(b), 0n, 0n, 0n, 0n);
            say("aio_init(" + a + "," + b + ")=" + String(r));
            shout("aio " + a + "," + b + "=" + String(r));
            if (r === 0n) {
                try {
                    const c = await syscall(0x29Cn, 0n, 0n, 0n, 0n, 0n, 0n);
                    say("aio_create(0)=" + String(c));
                    shout("create=" + String(c));
                } catch (e) { say("create threw: " + (e && e.message)); shout("create THREW"); }
            }
        } catch (e) { say("aio_init threw: " + (e && e.message)); shout("aio THREW"); }
    }

    try {
        const c2 = await syscall(0x29Cn, 0n, 0n, 0n, 0n, 0n, 0n);
        say("aio_create-alone(0)=" + String(c2));
        shout("create-alone=" + String(c2));
    } catch (e) { say("create-alone threw: " + (e && e.message)); shout("create-alone THREW"); }

    say("aioprobe done");
    shout("aio: done");
})()
