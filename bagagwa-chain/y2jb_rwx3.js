// y2jb_rwx3.js -- is a plain-mmap(RWX) page executable, or is `syscall` the problem?
// Send: python payload_sender.py <PS5-IP> <PORT> y2jb_rwx3.js
// Fresh boot first. Writes ONE byte (C3 = ret) into fresh RWX, reads it back,
// calls it. Survivor popup per step:
//   ret=<number>  => page IS executable; only the `syscall` insn faults.
//   crash at call => page is NOT executable (X silently stripped); user-RWX
//                    is dead and execution must come from runtime-owned pages.
(async () => {
    const LOG_HOST = "192.168.0.163"; // <-- your Mac IP
    const SZ = 0x4000n;
    const say = (s) => { try { log("[x3] " + s); } catch (e) {} };
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

    shout("x3: start");
    say("rwx3 start");
    let base = 0n;
    try {
        base = await syscall(N(0x1DD, "mmap"), 0n, SZ, 0x7n, 0x1002n, 0xFFFFFFFFn, 0n);
        say("rwx=" + hx(base)); shout("x3: rwx=" + hx(base));
        if (base === 0xFFFFFFFFFFFFFFFFn || base === 0n) { shout("x3: NOMAP, stop"); return; }
    } catch (e) { say("mmap threw: " + (e && e.message)); shout("x3: mmap THREW"); return; }
    try {
        write8(base, 0xC3);
        const b = Number(read8(base));
        say("byte=" + b.toString(16)); shout("x3: byte=" + b.toString(16));
        if (b !== 0xC3) return;
    } catch (e) { say("rw threw: " + (e && e.message)); shout("x3: rw THREW"); return; }
    try {
        const r = await call(base);
        say("call-ret=" + String(r)); shout("x3: ret=" + String(r));
    } catch (e) { say("call threw: " + (e && e.message)); shout("x3: call THREW"); }
    say("rwx3 done");
    shout("x3: done");
})()
