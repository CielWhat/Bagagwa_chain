// y2jb_probe4.js -- three independent questions, survivor marks throughout.
// Send: python payload_sender.py <PS5-IP> <PORT> y2jb_probe4.js
// Fresh boot first.
// Q1: is the runtime ROP region READABLE? (read 1 byte at ROP.ret, expect C3)
// Q2: does kqueueex (0x8D) dispatch? (p2jb lottery: mapped => p2jb path lives)
// Q3: dlsym arity (needed to use it later).
(async () => {
    const LOG_HOST = "192.168.0.163"; // <-- your Mac IP
    const say = (s) => { try { log("[p4] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const G = (n) => { try { return eval(n); } catch (e) { return undefined; } };

    shout("p4: start");
    say("probe4 start");

    try {
        const R = G("ROP");
        const b = read8(R.ret);
        say("ropbyte=" + Number(b).toString(16));
        shout("p4: ropread=" + Number(b).toString(16));
    } catch (e) { say("ropread threw: " + (e && e.message)); shout("p4: ropread THREW"); }

    try {
        const r = await syscall(0x8Dn, 0n, 0n, 0n, 0n, 0n, 0n);
        say("kqueueex=" + String(r));
        shout("p4: kqex=" + String(r));
    } catch (e) { say("kqueuex threw: " + (e && e.message)); shout("p4: kqex THREW"); }

    try {
        const d = G("dlsym");
        say("dlsym-arity=" + (typeof d === "function" ? d.length : "not-a-function"));
        shout("p4: dlsym-arity=" + (typeof d === "function" ? d.length : "no"));
    } catch (e) { say("dlsym threw: " + (e && e.message)); shout("p4: dlsym THREW"); }

    say("probe4 done");
    shout("p4: done");
})()
