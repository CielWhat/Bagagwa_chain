// y2jb_callstub2.js -- same mechanism, DIFFERENT offset (notification 0x48B0).
// Send: python payload_sender.py <PS5-IP> <PORT> y2jb_callstub2.js
// Fresh boot first. Decides address-specific vs module-wide:
//   survives (any -1/number) => 0x1B860 was just a wrong address; try others.
//   dies identically          => call() cannot reach this module at all
//                                (allowlist or wrong-module-base); call-stubs
//                                abandoned, ROP-thread path is the only door.
// ALSO: paste TERMINAL lines this time (y2jb.log), not just popups -- the
// libkernel_base= value is needed for analysis.
(async () => {
    const LOG_HOST = "192.168.0.163"; // <-- your Mac IP
    const say = (s) => { try { log("[c2] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const G = (n) => { try { return eval(n); } catch (e) { return undefined; } };
    const hx = (v) => { try { return "0x" + (BigInt(v) & 0xFFFFFFFFFFFFFFFFn).toString(16); } catch (e) { return "?"; } };
    const STUB_NOTIFY = 0x48B0n;

    shout("c2: start");
    say("callstub2 start");
    let kb = 0n;
    try {
        const b = G("libkernel_base");
        if (typeof b !== "bigint") { say("libkernel_base absent, stop"); shout("c2: NOBASE stop"); return; }
        kb = b;
        say("libkernel_base=" + hx(kb));
    } catch (e) { say("base threw: " + (e && e.message)); shout("c2: BASE THREW"); return; }
    try {
        const c = G("call");
        if (typeof c !== "function") { say("no call fn, stop"); shout("c2: NOCALL stop"); return; }
        const r = await c(kb + STUB_NOTIFY);
        say("stub-notify=" + String(r));
        shout("c2: notify=" + String(r));
    } catch (e) { say("stub-notify threw: " + (e && e.message)); shout("c2: notify THREW"); return; }
    say("callstub2 done");
    shout("c2: done");
})()
