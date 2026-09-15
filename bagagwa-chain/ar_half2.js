// y2jb_aioreal.js -- same numbers, VALID args (real pipe, real structs).
// Send: python payload_sender.py <PS5-IP> <PORT> y2jb_aioreal.js
// Fresh boot first. NULL args can crash where valid structs get clean
// errors, so this re-tests the needy calls properly:
//   pipe2 -> real fds | submit(0, real_req, 1) | create(1) | osem(valid)
// Survivor popup after every call; a crash fingers that exact call.
// Closes its pipe before exiting (no fd leaks across runs).
(async () => {
    const LOG_HOST = "192.168.0.163"; // <-- your Mac IP
    const say = (s) => { try { log("[ar] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    let net = "OFF";
    try { net = (typeof NETWORK_LOGGING !== "undefined" && NETWORK_LOGGING) ? "ON" : "OFF"; } catch (e) {}

    shout("ar-half2: start");
    say("half2 start");
    try {
        const r = await syscall(0x29Cn, 1n, 0n, 0n, 0n, 0n, 0n);
        say("create(1)=" + String(r));
        shout("ar: create=" + String(r));
    } catch (e) { say("create threw: " + (e && e.message)); shout("ar: create THREW"); }

    try {
        const nm = malloc(32);
        for (let i = 0; i < 32; i++) write8(nm + BigInt(i), 0);
        write8(nm, 116);
        const at = malloc(0x20);
        for (let i = 0; i < 0x20; i++) write8(at + BigInt(i), 0);
        write32(at, 1);
        write32(at + 8n, 1);
        const r = await syscall(0x225n, nm, at, 0n, 0n, 0n, 0n);
        say("osem_create=" + String(r));
        shout("ar: osem=" + String(r));
        try { if (r >= 0n) await syscall(0x226n, r, 0n, 0n, 0n, 0n, 0n); } catch (e) {}
    } catch (e) { say("osem threw: " + (e && e.message)); shout("ar: osem THREW"); }

    try {
        if (rfd >= 0) await syscall(0x06n, BigInt(rfd), 0n, 0n, 0n, 0n, 0n);
        if (wfd >= 0) await syscall(0x06n, BigInt(wfd), 0n, 0n, 0n, 0n, 0n);
    } catch (e) {}
    say("aioreal done");
    shout("ar: done");
})()
