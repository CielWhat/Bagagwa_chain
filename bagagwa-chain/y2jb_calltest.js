// y2jb_calltest.js -- one unknown syscall at a time, survivor marks via popup.
// Send: python payload_sender.py <PS5-IP> <PORT> y2jb_calltest.js
// Needs y2jb_logserver.py running (extra lines land in terminal too).
// Narrates fully through send_notification, so the TV alone tells the story:
//   "ct: start" -> "ct: 29E=..." -> "ct: 2AF=..." -> "ct: 16A=..." -> "ct: done"
// A crash between two popups fingers the call in between. Nothing is stored,
// no state changes except one throwaway pipe (closed right after).
(async () => {
    const LOG_HOST = "192.168.0.163"; // <-- your Mac IP
    const say = (s) => { try { log("[ct] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    let ctnet = "OFF";
    try { ctnet = (typeof NETWORK_LOGGING !== "undefined" && NETWORK_LOGGING) ? "ON" : "OFF"; } catch (e) {}

    shout("ct: start net=" + ctnet);
    say("calltest start");

    // 1) aio_init(0, 0) -- the prime suspect (first unknown call in stage0)
    try {
        const r = await syscall(0x29En, 0n, 0n, 0n, 0n, 0n, 0n);
        say("aio_init ret=" + String(r));
        shout("ct: 29E=" + String(r));
    } catch (e) { say("aio_init threw: " + (e && e.message)); shout("ct: 29E THREW"); }

    // 2) pipe2(&fds, 0) -- needs a pointer arg; fds read back + closed after
    try {
        const a = malloc(8);
        write64(a, 0n);
        const r = await syscall(0x2AFn, a, 0n, 0n, 0n, 0n, 0n);
        const fds = read64(a);
        const rfd = Number(fds & 0xFFFFFFFFn), wfd = Number((fds >> 32n) & 0xFFFFFFFFn);
        say("pipe2 ret=" + String(r) + " rfd=" + rfd + " wfd=" + wfd);
        shout("ct: 2AF=" + String(r) + " fds=" + rfd + "," + wfd);
        try { await syscall(0x06n, BigInt(rfd)); } catch (e) {}
        try { await syscall(0x06n, BigInt(wfd)); } catch (e) {}
    } catch (e) { say("pipe2 threw: " + (e && e.message)); shout("ct: 2AF THREW"); }

    // 3) kqueue() -- returns fd, closed after
    try {
        const r = await syscall(0x16An, 0n, 0n, 0n, 0n, 0n, 0n);
        say("kqueue ret=" + String(r));
        shout("ct: 16A=" + String(r));
        try { await syscall(0x06n, r); } catch (e) {}
    } catch (e) { say("kqueue threw: " + (e && e.message)); shout("ct: 16A THREW"); }

    say("calltest done");
    shout("ct: done");
})()
