// y2jb_bases.js -- which module bases does this runtime expose?
// Send: python payload_sender.py <PS5-IP> <PORT> y2jb_bases.js
// Fresh boot first. Pure reads of JS variables (typeof + value print).
// ZERO memory reads, ZERO calls, cannot crash. Decides whether the
// Y2_OFFSET_1340 table family is addressable on this exact build.
(async () => {
    const LOG_HOST = "192.168.0.163"; // <-- your Mac IP
    const say = (s) => { try { log("[bs] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const G = (n) => { try { return eval(n); } catch (e) { return undefined; } };
    const hx = (v) => { try { return "0x" + (BigInt(v) & 0xFFFFFFFFFFFFFFFFn).toString(16); } catch (e) { return "?"; } };

    shout("bs: start");
    say("bases probe start");
    for (const n of ["libcobalt_base", "libc_base", "libstarboard_base",
        "libkernel_base", "libSceNKWebKit_base", "webkit_base", "kernel_base"]) {
        const v = G(n);
        say(n + ": " + typeof v + (typeof v === "bigint" ? "=" + hx(v) : ""));
    }
    try {
        const R = G("ROP");
        say("ROP.ret=" + hx(R.ret));
        shout("bs: ret=" + hx(R.ret));
    } catch (e) { say("ROP.ret threw: " + (e && e.message)); }
    say("bases probe done");
    shout("bs: done");
})()
