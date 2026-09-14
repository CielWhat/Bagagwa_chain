// y2jb_probe.js -- safe capability probe for the Y2JB remote-JS runtime.
// Send with payload_sender.py:  python payload_sender.py <PS5-IP> <PORT> y2jb_probe.js
// (PORT = whatever your Y2JB remote JS server listens on.)
// Terminal logging: run y2jb_logserver.py on this Mac first (port 8080).
//   The probe points the console at it (LOG_HOST below) so every log() line
//   also lands in your terminal. Key answers additionally go out via
//   send_notification, so the TV screen shows them even if logging is off.
// Does: lists runtime globals, tests userland R/W (16 bytes), calls getpid.
// Everything is guarded -- worst case it prints what is missing, never crashes.
(async () => {
    const LOG_HOST = "192.168.0.163"; // <-- your Mac IP
    const rep = (s) => { try { log(s); } catch (e) {} };
    const G = (n) => { try { return eval(n); } catch (e) { return undefined; } };
    const seen = {};

    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    try {
        seen.net = (typeof NETWORK_LOGGING !== "undefined" && NETWORK_LOGGING) ? "ON" : "OFF";
    } catch (e) { seen.net = "unknown"; }

    rep("y2jb-probe start net=" + seen.net);
    try { rep("eval-selftest: " + typeof eval("41")); } catch (e) { rep("eval blocked"); }

    const names = ["malloc", "syscall", "SYSCALL", "ROP",
        "read64", "write64", "read32", "write32", "read8", "write8",
        "read16", "write16", "TITLE_ID", "get_title_id", "version_string",
        "ipv6_kernel_rw", "is_jailbroken", "file_exists", "read_file",
        "log", "send_notification"];
    for (const n of names) {
        const v = G(n);
        let d = typeof v;
        try {
            if (typeof v === "string" && v.length <= 48) d += "=" + v;
            else if (typeof v === "bigint") d += "=" + v.toString();
            else if (typeof v === "function") d += " arity=" + v.length;
        } catch (e) {}
        if (n === "malloc" || n === "syscall" || n === "SYSCALL" || n === "ROP") {
            seen[n] = (typeof v === "function" || typeof v === "object") ? "yes" : "no";
        }
        rep("typeof " + n + ": " + d);
    }

    try {
        const S = G("SYSCALL");
        if (S && (typeof S === "object" || typeof S === "function")) {
            const ks = Object.keys(S);
            rep("SYSCALL keys: " + ks.length + " e.g. " + ks.slice(0, 14).join(","));
        } else { rep("SYSCALL: not-an-object"); }
    } catch (e) { rep("SYSCALL list threw: " + (e && e.message)); }

    try {
        const R = G("ROP");
        if (R && (typeof R === "object" || typeof R === "function")) {
            const ks = Object.keys(R);
            rep("ROP keys: " + ks.length + " e.g. " + ks.slice(0, 14).join(","));
        } else { rep("ROP: not-an-object"); }
    } catch (e) { rep("ROP list threw: " + (e && e.message)); }

    try {
        const m = G("malloc"), w = G("write64"), r = G("read64");
        if (typeof m === "function" && typeof w === "function" && typeof r === "function") {
            const p = await m(16);
            rep("malloc-type: " + typeof p + " val=" + String(p));
            await w(p, 0x1122334455667788n);
            const v = await r(p);
            seen.rw = (v === 0x1122334455667788n) ? "OK" : "MISMATCH";
            rep("rw-test: " + seen.rw + " got " + String(v));
        } else { seen.rw = "SKIP"; rep("rw-test: SKIP (need malloc+write64+read64)"); }
    } catch (e) { seen.rw = "THREW"; rep("rw-test threw: " + (e && e.message)); }

    try {
        const sc = G("syscall");
        if (typeof sc === "function") {
            const r = await sc(0x14n);
            seen.pid = String(r);
            rep("getpid: " + String(r));
        } else { seen.pid = "SKIP"; rep("getpid: SKIP (no syscall fn)"); }
    } catch (e) { seen.pid = "THREW"; rep("getpid threw: " + (e && e.message)); }

    rep("y2jb-probe done");
    try {
        send_notification("probe net=" + seen.net + " malloc=" + (seen.malloc || "?") +
            " syscall=" + (seen.syscall || "?") + " rw=" + (seen.rw || "?") +
            " pid=" + (seen.pid || "?"));
    } catch (e) {}
})()
