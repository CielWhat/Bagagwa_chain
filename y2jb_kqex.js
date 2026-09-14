// y2jb_kqex.js -- does kqueueex (0x8D) dispatch via direct call?
// Send: python payload_sender.py <PS5-IP> <PORT> y2jb_kqex.js
// Fresh boot first. ONE call, zero args (error paths only, nothing stored).
//   "kq: ex=-1"  => mapped-but-refusing (p2jb path needs kernel offsets next)
//   crash        => unmapped like the aio pair (direct path fully mapped out)
// Either way this is the last dispatch question; no more mapping runs after.
(async () => {
    const LOG_HOST = "192.168.0.163"; // <-- your Mac IP
    const say = (s) => { try { log("[kq] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    let net = "OFF";
    try { net = (typeof NETWORK_LOGGING !== "undefined" && NETWORK_LOGGING) ? "ON" : "OFF"; } catch (e) {}

    shout("kq: start net=" + net);
    say("kqex start");
    try {
        const r = await syscall(0x8Dn, 0n, 0n, 0n, 0n, 0n, 0n);
        say("kqueueex=" + String(r));
        shout("kq: ex=" + String(r));
    } catch (e) { say("kqueuex threw: " + (e && e.message)); shout("kq: ex THREW"); }
    say("kqex done");
    shout("kq: done");
})()
