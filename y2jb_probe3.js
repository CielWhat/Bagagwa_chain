// y2jb_probe3.js -- ROP-path feasibility: call/syscall_wrapper/dlsym presence
// + SAFELY calling a bare `ret` gadget (returns cleanly if call works).
// Send: python payload_sender.py <PS5-IP> <PORT> y2jb_probe3.js
// Fresh boot first. Narrates via popups; a crash fingers that exact step.
(async () => {
    const LOG_HOST = "192.168.0.163"; // <-- your Mac IP
    const say = (s) => { try { log("[p3] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const G = (n) => { try { return eval(n); } catch (e) { return undefined; } };
    let net = "OFF";
    try { net = (typeof NETWORK_LOGGING !== "undefined" && NETWORK_LOGGING) ? "ON" : "OFF"; } catch (e) {}

    shout("p3: start net=" + net);
    say("probe3 start");

    for (const n of ["call", "syscall_wrapper", "dlsym", "longjmp", "setjmp"]) {
        const v = G(n);
        let d = typeof v;
        try { if (typeof v === "bigint") d += "=0x" + v.toString(16); } catch (e) {}
        say("typeof " + n + ": " + d);
    }

    try {
        const R = G("ROP");
        const c = G("call");
        if (R && typeof R.ret !== "undefined" && typeof c === "function") {
            say("ROP.ret=0x" + R.ret.toString(16));
            const r = await c(R.ret);
            say("call(ret)=" + String(r));
            shout("p3: retcall=" + String(r));
        } else { say("retcall SKIP (need ROP.ret + call)"); shout("p3: retcall SKIP"); }
    } catch (e) { say("retcall threw: " + (e && e.message)); shout("p3: retcall THREW"); }

    say("probe3 done");
    shout("p3: done");
})()
