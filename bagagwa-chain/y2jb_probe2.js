// y2jb_probe2.js -- errno-convention + inventory probe (all safe calls).
// Send: python payload_sender.py <PS5-IP> <PORT> y2jb_probe2.js
// Needs y2jb_logserver.py running on this Mac (port 8080).
// Tests: getpid x2 (determinism), getuid, close(0xFFFFFFFF) (EBADF encoding),
// is_jailbroken(), full SYSCALL + ROP key lists. No state changes anywhere.
(async () => {
    const LOG_HOST = "192.168.0.163"; // <-- your Mac IP
    const rep = (s) => { try { log(s); } catch (e) {} };
    const G = (n) => { try { return eval(n); } catch (e) { return undefined; } };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}

    const show = (v) => {
        try {
            if (typeof v !== "bigint") return typeof v + ":" + String(v).slice(0, 60);
            const u = v & 0xFFFFFFFFFFFFFFFFn;
            const s = (u >= 0x8000000000000000n) ? u - 0x10000000000000000n : u;
            return "u=0x" + u.toString(16) + " s=" + s.toString();
        } catch (e) { return "unprintable"; }
    };
    const sc = G("syscall");
    if (typeof sc !== "function") {
        rep("probe2: NO syscall fn, aborting");
        try { send_notification("probe2: no syscall"); } catch (e) {}
        return;
    }

    rep("probe2 start");
    try {
        const a = await sc(0x14n);
        const b = await sc(0x14n);
        rep("getpid x2: " + show(a) + " / " + show(b));
    } catch (e) { rep("getpid threw: " + (e && e.message)); }

    try {
        const u = await sc(0x18n);
        rep("getuid: " + show(u));
    } catch (e) { rep("getuid threw: " + (e && e.message)); }

    try {
        const c = await sc(0x06n, 0xFFFFFFFFn);
        rep("close(badfd) [expect EBADF=9]: " + show(c));
    } catch (e) { rep("close threw: " + (e && e.message)); }

    try {
        const jb = G("is_jailbroken");
        if (typeof jb === "function") rep("is_jailbroken: " + String(await jb()));
        else rep("is_jailbroken: absent");
    } catch (e) { rep("is_jailbroken threw: " + (e && e.message)); }

    try {
        const S = G("SYSCALL");
        rep("SYSCALL all: " + Object.keys(S).join(","));
    } catch (e) { rep("SYSCALL list threw: " + (e && e.message)); }

    try {
        const R = G("ROP");
        rep("ROP all: " + Object.keys(R).join(","));
    } catch (e) { rep("ROP list threw: " + (e && e.message)); }

    rep("probe2 done");
    try { send_notification("probe2 done - see log"); } catch (e) {}
})()
