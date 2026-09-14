// y2jb_rwx2.js -- prove write + execute + arg-forwarding on plain mmap(RWX).
// Send: python payload_sender.py <PS5-IP> <PORT> y2jb_rwx2.js
// Fresh boot first. One RWX page, seven tiny stubs:
//   +0x00: getpid                     (B8 14 00 00 00 0F 05 C3) -> expect 159
//   +0x10: return rdi  (48 89 F8 C3)  +0x20: return rsi (48 89 F0 C3)
//   +0x30: return rdx  (48 89 D0 C3)  +0x40: return rcx (48 89 C8 C3)
//   +0x50: return r8   (4C 89 C0 C3)  +0x60: return r9  (4C 89 C8 C3)
// Called with (0x11,0x22,0x33,0x44,0x55,0x66): each return identifies its
// register. Survivor popup per call; a crash fingers that exact step.
(async () => {
    const LOG_HOST = "192.168.0.163"; // <-- your Mac IP
    const SZ = 0x4000n;
    const say = (s) => { try { log("[x2] " + s); } catch (e) {} };
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

    shout("x2: start");
    say("rwx2 start");
    let base = 0n;
    try {
        base = await syscall(N(0x1DD, "mmap"), 0n, SZ, 0x7n, 0x1002n, 0xFFFFFFFFn, 0n);
        say("rwx=" + hx(base)); shout("x2: rwx=" + hx(base));
        if (base === 0xFFFFFFFFFFFFFFFFn || base === 0n) { shout("x2: NOMAP, stop"); return; }
    } catch (e) { say("mmap threw: " + (e && e.message)); shout("x2: mmap THREW"); return; }

    const stubs = [
        ["getpid", 0x00, [0xB8, 0x14, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3], []],
        ["rdi", 0x10, [0x48, 0x89, 0xF8, 0xC3], [0x11n]],
        ["rsi", 0x20, [0x48, 0x89, 0xF0, 0xC3], [0x11n, 0x22n]],
        ["rdx", 0x30, [0x48, 0x89, 0xD0, 0xC3], [0x11n, 0x22n, 0x33n]],
        ["rcx", 0x40, [0x48, 0x89, 0xC8, 0xC3], [0x11n, 0x22n, 0x33n, 0x44n]],
        ["r8", 0x50, [0x4C, 0x89, 0xC0, 0xC3], [0x11n, 0x22n, 0x33n, 0x44n, 0x55n]],
        ["r9", 0x60, [0x4C, 0x89, 0xC8, 0xC3], [0x11n, 0x22n, 0x33n, 0x44n, 0x55n, 0x66n]],
    ];
    try {
        for (const st of stubs) {
            for (let i = 0; i < st[2].length; i++) write8(base + BigInt(st[1] + i), st[2][i]);
        }
        let ok = true;
        for (const st of stubs) {
            for (let i = 0; i < st[2].length; i++) {
                if (Number(read8(base + BigInt(st[1] + i))) !== st[2][i]) ok = false;
            }
        }
        say("writeback=" + (ok ? "OK" : "MISMATCH")); shout("x2: bytes=" + (ok ? "OK" : "BAD"));
        if (!ok) return;
    } catch (e) { say("writeback threw: " + (e && e.message)); shout("x2: bytes THREW"); return; }

    for (const st of stubs) {
        try {
            const r = await call(base + BigInt(st[1]), ...st[3]);
            say("call " + st[0] + "=" + String(r)); shout("x2: " + st[0] + "=" + String(r));
        } catch (e) { say("call " + st[0] + " threw: " + (e && e.message)); shout("x2: " + st[0] + " THREW"); }
    }
    say("rwx2 done");
    shout("x2: done");
})()
