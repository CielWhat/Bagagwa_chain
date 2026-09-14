// y2jb_rwx.js -- prove executable memory + hand-built syscall stubs.
// Send: python payload_sender.py <PS5-IP> <PORT> y2jb_rwx.js
// Fresh boot first. Recipe mirrors p2jb.js lines 2060-2068 (jitshm dance):
//   exec = jitshm_create(0, 0x4000, 0x7) | write = jitshm_alias(exec, 0x3)
//   W view = mmap(kernel-picked, RW, FIXED+SHARED, write)
//   X view = mmap(kernel-picked, RWX, FIXED+SHARED, exec)
//   write [B8 14 00 00 00 0F 05 C3] (getpid stub) via W, call() via X.
// Survivor popup after EVERY step. Expect getpid=159 at the end.
// Fallback: if jitshm fails, one plain mmap(RWX) attempt (likely denied).
(async () => {
    const LOG_HOST = "192.168.0.163"; // <-- your Mac IP
    const SZ = 0x4000n;
    const say = (s) => { try { log("[rwx] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const hx = (v) => { try { return "0x" + (BigInt(v) & 0xFFFFFFFFFFFFFFFFn).toString(16); } catch (e) { return "?"; } };
    const N = (n, nm) => {
        try {
            const S = eval("SYSCALL");
            if (S && S[nm] !== undefined) return BigInt(S[nm]);
        } catch (e) {}
        return BigInt(n);
    };
    let net = "OFF";
    try { net = (typeof NETWORK_LOGGING !== "undefined" && NETWORK_LOGGING) ? "ON" : "OFF"; } catch (e) {}

    shout("rwx: start net=" + net);
    say("rwx start");

    let e = -1n, w = -1n, bw = 0n, bx = 0n;
    try {
        e = await syscall(N(0x215,"jitshm_create"), 0n, SZ, 0x7n, 0n, 0n, 0n);
        say("jitshm_create=" + hx(e)); shout("rwx: exec=" + hx(e));
    } catch (er) { say("create threw: " + (er && er.message)); shout("rwx: exec THREW"); }
    try {
        w = await syscall(N(0x216,"jitshm_alias"), e, 0x3n, 0n, 0n, 0n, 0n);
        say("jitshm_alias=" + hx(w)); shout("rwx: write=" + hx(w));
    } catch (er) { say("alias threw: " + (er && er.message)); shout("rwx: write THREW"); }

    const okE = (typeof e === "bigint" && e !== 0xFFFFFFFFFFFFFFFFn && e !== 0n);
    const okW = (typeof w === "bigint" && w !== 0xFFFFFFFFFFFFFFFFn && w !== 0n);
    if (okE && okW) {
        try {
            bw = await syscall(N(0x1DD,"mmap"), 0n, SZ, 0x3n, 0x1002n, 0xFFFFFFFFn, 0n);
            say("anonW=" + hx(bw));
            const r1 = await syscall(N(0x1DD,"mmap"), bw, SZ, 0x3n, 0x11n, w, 0n);
            say("mapW=" + hx(r1)); shout("rwx: W=" + hx(r1));
        } catch (er) { say("mapW threw: " + (er && er.message)); shout("rwx: W THREW"); }
        try {
            const t = await syscall(N(0x1DD,"mmap"), 0n, SZ, 0x3n, 0x1002n, 0xFFFFFFFFn, 0n);
            say("anonX=" + hx(t));
            const r2 = await syscall(N(0x1DD,"mmap"), t, SZ, 0x7n, 0x11n, e, 0n);
            say("mapX=" + hx(r2)); shout("rwx: X=" + hx(r2));
            bx = t;
        } catch (er) { say("mapX threw: " + (er && er.message)); shout("rwx: X THREW"); }
        try {
            const stub = [0xB8, 0x14, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3];
            for (let i = 0; i < stub.length; i++) write8(bw + BigInt(i), stub[i]);
            let back = "";
            for (let i = 0; i < stub.length; i++) back += read8(bw + BigInt(i)).toString(16).padStart(2, "0");
            say("stub-bytes=" + back); shout("rwx: bytes=" + back);
        } catch (er) { say("writeback threw: " + (er && er.message)); shout("rwx: bytes THREW"); }
        try {
            const r = await call(bx);
            say("call-stub getpid=" + String(r)); shout("rwx: getpid=" + String(r));
        } catch (er) { say("call threw: " + (er && er.message)); shout("rwx: call THREW"); }
    } else {
        say("jitshm path dead, trying plain mmap RWX");
        try {
            const r = await syscall(N(0x1DD,"mmap"), 0n, SZ, 0x7n, 0x1002n, 0xFFFFFFFFn, 0n);
            say("plainRWX=" + hx(r)); shout("rwx: plain=" + hx(r));
        } catch (er) { say("plain threw: " + (er && er.message)); shout("rwx: plain THREW"); }
    }

    say("rwx done");
    shout("rwx: done");
})()
