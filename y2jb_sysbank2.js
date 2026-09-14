// y2jb_sysbank2.js -- feasibility batch for the kqueueex path.
// Send: python payload_sender.py <PS5-IP> <PORT> y2jb_sysbank2.js
// Fresh boot first. Safe shapes only (invalid fds, NULL ptrs, real buffers);
// worst case is a clean -1 or an app crash that fingers one number.
// Part 1 (zero crash risk): typeof hunt for threading primitives.
// Part 2 (adaptive): socketpair -> real fds unlock REAL follow-up calls.
(async () => {
    const LOG_HOST = "192.168.0.163"; // <-- your Mac IP
    const say = (s) => { try { log("[sb] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const G = (n) => { try { return eval(n); } catch (e) { return undefined; } };
    const hx = (v) => { try { return "0x" + (BigInt(v) & 0xFFFFFFFFFFFFFFFFn).toString(16); } catch (e) { return "?"; } };

    shout("sb: start");
    say("sysbank2 start");

    for (const n of ["Thrd_create", "pthread_create", "scePthreadCreate",
        "longjmp", "setjmp", "Worker", "spawn", "thread_create",
        "libc_base", "libkernel_base", "thread", "pthread_join"]) {
        const v = G(n);
        let d = typeof v;
        try { if (typeof v === "bigint") d += "=" + hx(v); } catch (e) {}
        say("typeof " + n + ": " + d);
    }
    shout("sb: typeofs done");

    const sc = G("syscall");
    if (typeof sc !== "function") { say("no syscall, stop"); shout("sb: stop"); return; }
    const C = async (tag, num, args) => {
        try {
            const r = await sc(BigInt(num), ...args);
            say(tag + "=" + String(r));
            shout("sb: " + tag + "=" + String(r));
            return r;
        } catch (e) { say(tag + " threw: " + (e && e.message)); shout("sb: " + tag + " THREW"); return null; }
    };
    const Z = [0n, 0n, 0n, 0n, 0n, 0n];

    let sv0 = -1, sv1 = -1;
    try {
        const sv = malloc(8);
        write64(sv, 0n);
        const r = await sc(0x87n, 1n, 1n, 0n, sv, 0n, 0n);
        const v = read64(sv);
        sv0 = Number(v & 0xFFFFFFFFn); sv1 = Number((v >> 32n) & 0xFFFFFFFFn);
        say("socketpair=" + String(r) + " fds=" + sv0 + "," + sv1);
        shout("sb: sp=" + String(r) + " " + sv0 + "," + sv1);
    } catch (e) { say("socketpair threw: " + (e && e.message)); shout("sb: sp THREW"); }

    try {
        const ua = malloc(16);
        for (let i = 0; i < 16; i++) write8(ua + BigInt(i), 0);
        const r = await sc(0x1C6n, ua, 3n, 0n, 0n, 0n, 0n);
        say("umtx_wake=" + String(r)); shout("sb: umtx=" + String(r));
    } catch (e) { say("umtx threw: " + (e && e.message)); shout("sb: umtx THREW"); }

    await C("cpuset", 0x1E7, Z);
    await C("rtprio", 0x1D2, Z);
    await C("setrlimit", 0xC3, Z);
    await C("open", 0x05, Z);

    try {
        const r = await sc(0x49n, 0n, 0n, 0n, 0n, 0n, 0n);
        say("mprotect0=" + String(r)); shout("sb: mprot=" + String(r));
    } catch (e) { say("mprotect threw: " + (e && e.message)); shout("sb: mprot THREW"); }

    if (sv0 >= 0 && sv1 >= 0) {
        try {
            const b = malloc(16);
            for (let i = 0; i < 16; i++) write8(b + BigInt(i), 65);
            const w = await sc(0x04n, BigInt(sv1), b, 8n, 0n, 0n, 0n);
            const rb = malloc(16);
            for (let i = 0; i < 16; i++) write8(rb + BigInt(i), 0);
            const r = await sc(0x03n, BigInt(sv0), rb, 8n, 0n, 0n, 0n);
            let s = "";
            for (let i = 0; i < 8; i++) s += String.fromCharCode(Number(read8(rb + BigInt(i))));
            say("sockpipe w=" + String(w) + " r=" + String(r) + " data=" + s);
            shout("sb: pipe w=" + String(w) + " r=" + String(r));
        } catch (e) { say("sockpipe threw: " + (e && e.message)); shout("sb: pipe THREW"); }
        try { await sc(0x06n, BigInt(sv0), 0n, 0n, 0n, 0n, 0n); } catch (e) {}
        try { await sc(0x06n, BigInt(sv1), 0n, 0n, 0n, 0n, 0n); } catch (e) {}
    } else { say("sockpipe SKIP (no fds)"); }

    say("sysbank2 done");
    shout("sb: done");
})()
