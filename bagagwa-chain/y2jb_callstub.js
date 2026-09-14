// y2jb_callstub.js -- prove the call-stub model: libkernel_base + predicted
// stub RVAs, invoked via call(), bypassing direct dispatch entirely.
// Send: python payload_sender.py <PS5-IP> <PORT> y2jb_callstub.js
// Fresh boot first. Two calls, survivor popup after each:
//   1) getpid stub (base+0x1B860), no args -> expect 159 (CONTROL: proves
//      base + table + call-as-stub-function end to end)
//   2) aio_init stub (base+0x1D2E0) with (0,0) -> expect -1 clean refusal
//      (proves AIO stub addresses work via call(); -1 means "refused", same
//      as direct). A crash fingers that exact address as wrong.
(async () => {
    const LOG_HOST = "192.168.0.163"; // <-- your Mac IP
    const say = (s) => { try { log("[cs] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const G = (n) => { try { return eval(n); } catch (e) { return undefined; } };
    const hx = (v) => { try { return "0x" + (BigInt(v) & 0xFFFFFFFFFFFFFFFFn).toString(16); } catch (e) { return "?"; } };
    // Predicted 13.40 stub RVAs (12.00 syscall_map +0x90; getpid 5x verified).
    const STUB_GETPID = 0x1B860n;
    const STUB_AIO_INIT = 0x1D2E0n;

    shout("cs: start");
    say("callstub start");
    let kb = 0n;
    try {
        const b = G("libkernel_base");
        if (typeof b !== "bigint") { say("libkernel_base absent, stop"); shout("cs: NOBASE stop"); return; }
        kb = b;
        say("libkernel_base=" + hx(kb));
    } catch (e) { say("base threw: " + (e && e.message)); shout("cs: BASE THREW"); return; }
    try {
        const c = G("call");
        if (typeof c !== "function") { say("no call fn, stop"); shout("cs: NOCALL stop"); return; }
        const r = await c(kb + STUB_GETPID);
        say("stub-getpid=" + String(r));
        shout("cs: getpid=" + String(r));
    } catch (e) { say("stub-getpid threw: " + (e && e.message)); shout("cs: getpid THREW"); return; }
    try {
        const c = G("call");
        const r = await c(kb + STUB_AIO_INIT, 0n, 0n);
        say("stub-aio_init(0,0)=" + String(r));
        shout("cs: init=" + String(r));
    } catch (e) { say("stub-aio_init threw: " + (e && e.message)); shout("cs: init THREW"); }
    say("callstub done");
    shout("cs: done");
})()
