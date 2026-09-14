// y2jb_dlsym.js -- can we resolve functions BY NAME (bypassing numbers)?
// Send: python payload_sender.py <PS5-IP> <PORT> y2jb_dlsym.js
// Fresh boot first. Resolution alone cannot crash anything sensitive:
// worst case it returns NULL/garbage (reported, never called here).
// Tries handles {0, -1} x names {getpid, aio_submit, osem_create, pipe2}.
// getpid MUST resolve if the mechanism works (control). Nothing is CALLED.
(async () => {
    const LOG_HOST = "192.168.0.163"; // <-- your Mac IP
    const say = (s) => { try { log("[dl] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const G = (n) => { try { return eval(n); } catch (e) { return undefined; } };
    const hx = (v) => { try { return "0x" + (BigInt(v) & 0xFFFFFFFFFFFFFFFFn).toString(16); } catch (e) { return "?"; } };

    shout("dl: start");
    say("dlsym probe start");
    try {
        const d = G("dlsym");
        say("dlsym-arity=" + (typeof d === "function" ? d.length : "not-a-function"));
        shout("dl: arity=" + (typeof d === "function" ? d.length : "no"));
        if (typeof d !== "function") { say("dlsym unusable, stop"); shout("dl: stop"); return; }
        const wstr = (addr, s) => {
            for (let i = 0; i < s.length; i++) write8(addr + BigInt(i), s.charCodeAt(i));
            write8(addr + BigInt(s.length), 0);
        };
        for (const h of [0n, 0xFFFFFFFFFFFFFFFFn]) {
            for (const nm of ["getpid", "aio_submit", "osem_create", "pipe2"]) {
                try {
                    const nb = malloc(32);
                    for (let i = 0; i < 32; i++) write8(nb + BigInt(i), 0);
                    wstr(nb, nm);
                    const out = malloc(8);
                    write64(out, 0n);
                    const r = await d(h, nb, out);
                    const v = read64(out);
                    say("dlsym h=" + hx(h) + " " + nm + " ret=" + String(r) + " out=" + hx(v));
                } catch (e) { say("dlsym " + nm + " threw: " + (e && e.message)); }
            }
        }
        shout("dl: done");
    } catch (e) { say("dlsym probe threw: " + (e && e.message)); shout("dl: THREW"); }
    say("dlsym probe done");
})()
