// ar_trace.js -- popup after EVERY step (TV popups survive kernel panic; log POSTs may not).
// Finds the exact crashing call: last popup seen = crash is the NEXT call.
(async () => {
    const say = (s) => { try { log("[tr] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://192.168.0.163:8080/log"; } catch (e) {}
    shout("tr: alive-0");
    say("trace start");
    try {
        const r = await syscall(0x29En, 0n, 0n, 0n, 0n, 0n, 0n);
        shout("tr: init-done " + String(r));
        say("init=" + String(r));
    } catch (e) { shout("tr: init THREW"); }
    let rfd = -1;
    try {
        const a = malloc(8);
        write64(a, 0n);
        const r = await syscall(0x2AFn, a, 0n, 0n, 0n, 0n, 0n);
        const fds = read64(a);
        rfd = Number(fds & 0xFFFFFFFFn);
        shout("tr: pipe-done " + String(r));
        say("pipe=" + String(r));
    } catch (e) { shout("tr: pipe THREW"); }
    try {
        const data = malloc(64);
        for (let i = 0; i < 64; i += 8) write64(data + BigInt(i), 0n);
        const req = malloc(0x40);
        for (let i = 0; i < 0x40; i += 8) write64(req + BigInt(i), 0n);
        write32(req, rfd >= 0 ? rfd : 0);
        write64(req + 8n, data);
        write64(req + 16n, 64n);
        shout("tr: struct-ready");
        const r = await syscall(0x295n, 0n, req, 1n, 0n, 0n, 0n);
        shout("tr: submit-done " + String(r));
        say("submit=" + String(r));
    } catch (e) { shout("tr: submit THREW"); }
    shout("tr: done");
    say("trace done");
})()
