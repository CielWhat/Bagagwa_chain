// y2jb_step1.js -- 9KB canary: proves the runtime loads+executes OUR code
// (BigInt, DataView, Map, padStart, asIntN, globalThis) with ZERO syscalls.
// Send first. If this runs, load/env is fine and the fault is elsewhere.
// (Built from y2jb_head.js + self-test; engine NOT included.)
(async () => {
    const Y2JB_MASK64 = 0xFFFFFFFFFFFFFFFFn;
    const LOG_HOST = "192.168.0.163"; // <-- your Mac IP
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}
    let tnet = "OFF";
    try { tnet = (typeof NETWORK_LOGGING !== "undefined" && NETWORK_LOGGING) ? "ON" : "OFF"; } catch (e) {}
    const t = ["net=" + tnet];
    try {
        t.push("bigint=" + (0x14n === 20n ? "ok" : "BAD"));
        t.push("dataview=" + (typeof DataView !== "undefined" ? "ok" : "MISSING"));
        t.push("asintn=" + (typeof BigInt.asIntN === "function" ? "ok" : "MISSING"));
        t.push("padstart=" + (typeof String.prototype.padStart === "function" ? "ok" : "MISSING"));
        t.push("globalThis=" + (typeof globalThis !== "undefined" ? "ok" : "MISSING"));
        t.push("map=" + (typeof Map !== "undefined" ? "ok" : "MISSING"));
        t.push("settimeout=" + (typeof setTimeout !== "undefined" ? "ok" : "MISSING"));
        const dv = new DataView(new ArrayBuffer(16));
        dv.setBigUint64(0, 0x1122334455667788n, true);
        t.push("dv-rw=" + (dv.getBigUint64(0, true) === 0x1122334455667788n ? "ok" : "BAD"));
        t.push("neg=" + (BigInt.asIntN(32, 0xFFFFFFFFn) === -1n ? "ok" : "BAD"));
        for (const s of t) { try { log("[bgw-t1] " + s); } catch (e) {} }
        try { send_notification("t1: " + t.join(" ").slice(0, 200)); } catch (e) {}
    } catch (e) {
        try { log("[bgw-t1] FATAL: " + ((e && e.message) || String(e))); } catch (_) {}
        try { send_notification("t1 FATAL"); } catch (_) {}
    }
})()
