// y2jb_numbank.js -- map which needed syscall numbers exist on 13.40.
// Send: python payload_sender.py <PS5-IP> <PORT> y2jb_numbank.js
// Fresh boot first. Each number is called once with zero args; survivor
// popups tell the tale (a crash fingers that number as unmapped).
// Zero-arg calls can only fail with errors (EINVAL/EFAULT/EBADF), never do
// anything -- except: worst case the whole PS5 reboots itself instead of
// just YouTube. That's normal in this game; it restarts fine.
// Skipped here: 0x297 multi_wait (might block instead of answering --
// tested later through the real stage flow) and numbers stages never call.
(async () => {
    const LOG_HOST = "192.168.0.163"; // <-- your Mac IP
    const say = (s) => { try { log("[nb] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    let net = "OFF";
    try { net = (typeof NETWORK_LOGGING !== "undefined" && NETWORK_LOGGING) ? "ON" : "OFF"; } catch (e) {}

    shout("nb: start net=" + net);
    say("numbank start");

    const T = [
        [0x225, "ocreate"], [0x228, "oclose"], [0x22B, "opost"], [0x295, "submit"],
        [0x298, "mpoll"], [0x296, "mdel"], [0x227, "oopen"], [0x226, "odelete"],
        [0x2D7, "dbg"], [0x29C, "create"]
    ];
    for (const pair of T) {
        const num = pair[0], tag = pair[1];
        try {
            const r = await syscall(BigInt(num), 0n, 0n, 0n, 0n, 0n, 0n);
            say(tag + " 0x" + num.toString(16) + "=" + String(r));
            shout("nb: " + tag + "=" + String(r));
        } catch (e) { say(tag + " threw: " + (e && e.message)); shout("nb: " + tag + " THREW"); }
    }

    say("numbank done");
    shout("nb: done");
})()
