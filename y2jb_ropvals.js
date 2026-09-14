// y2jb_ropvals.js -- print ROP property VALUES (+libcobalt_base if present).
// Send: python payload_sender.py <PS5-IP> <PORT> y2jb_ropvals.js
// Fresh boot first. ZERO memory reads, ZERO calls -- pure property access,
// cannot crash. Verifies a pasted ROP_1340 table offline by differences
// (ASLR-independent): R.pop_rdi - R.ret must equal 0x54B - 0x31, etc.
(async () => {
    const LOG_HOST = "192.168.0.163"; // <-- your Mac IP
    const say = (s) => { try { log("[rv] " + s); } catch (e) {} };
    const shout = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    const G = (n) => { try { return eval(n); } catch (e) { return undefined; } };
    const hx = (v) => { try { return "0x" + (BigInt(v) & 0xFFFFFFFFFFFFFFFFn).toString(16); } catch (e) { return "?"; } };

    shout("rv: start");
    say("ropvals start");
    try {
        const b = G("libcobalt_base");
        say("libcobalt_base: " + typeof b + (typeof b === "bigint" ? "=" + hx(b) : ""));
    } catch (e) { say("libcobalt_base threw: " + (e && e.message)); }
    try {
        const R = G("ROP");
        const names = ["pop_rsp", "pop_rax", "pop_rdi", "pop_rsi", "pop_rdx",
            "pop_rcx", "pop_r8", "pop_r9", "pop_rbp", "mov_qword_rdi_rax",
            "mov_qword_rdi_rdx", "mov_rax_0x200000000", "mov_rsp_rbp", "ret"];
        for (const n of names) {
            let v;
            try { v = R[n]; } catch (e) { say(n + " read threw"); continue; }
            say("ROP." + n + "=" + (typeof v === "bigint" || typeof v === "number" ? hx(v) : typeof v));
        }
    } catch (e) { say("ROP walk threw: " + (e && e.message)); }
    say("ropvals done");
    shout("rv: done");
})()
