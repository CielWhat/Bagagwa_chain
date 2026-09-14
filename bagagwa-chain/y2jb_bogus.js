// y2jb_bogus.js -- call a DEFINITELY-bogus syscall number once.
// Send: python payload_sender.py <PS5-IP> <PORT> y2jb_bogus.js
// Decisive discriminator for the aio_init(-1) mystery:
//   - crash with NO popups after "bg: start"  => unknown numbers explode,
//     so 0x29E's clean -1 proves it IS mapped (args/perm issue, not number).
//   - "bg: FFF0=-1" popup                    => unknown numbers also give -1,
//     so -1 tells nothing and we need the real errno (dlsym->__error path).
// Either way, one send settles it. Reboot the PS5 first (p2jb's own rule:
// runs after a crash are unreliable -- start every test from a fresh boot).
(async () => {
    const LOG_HOST = "192.168.0.163"; // <-- your Mac IP
    const say = (s) => { try { log("[bg] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    let net = "OFF";
    try { net = (typeof NETWORK_LOGGING !== "undefined" && NETWORK_LOGGING) ? "ON" : "OFF"; } catch (e) {}

    shout("bg: start net=" + net);
    say("bogus start");
    try {
        const r = await syscall(0xFFF0n, 0n, 0n, 0n, 0n, 0n, 0n);
        say("bogus FFF0=" + String(r));
        shout("bg: FFF0=" + String(r));
    } catch (e) { say("bogus threw: " + (e && e.message)); shout("bg: FFF0 THREW"); }
    say("bogus done");
    shout("bg: done");
})()
