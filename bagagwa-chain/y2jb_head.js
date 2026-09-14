// y2jb_head.js -- Y2JB BigInt-world adapter for the bagagwa.js engine.
// Classic script (no modules): defines y2jb_make_context() -> X context for
// makeBagagwaEngine(X). Concatenated ahead of the engine body + y2jb_run.js.
// Model: local Uint8Array shadows + remote Y2JB malloc; synced both ways
// around every syscall for pointer args. Defines ONLY y2jb_* top-level names
// (Y2JB globals malloc/syscall/read64/... are used read-only, never shadowed).

const Y2JB_MASK64 = 0xFFFFFFFFFFFFFFFFn;

// number | int64-shim | bigint -> BigInt value (immediates; NOT addresses)
function y2jb_toBig(n) {
    if (typeof n === "bigint") return n;
    if (typeof n === "number") {
        if (!Number.isFinite(n) || Math.floor(n) !== n || n < 0)
            throw new Error("y2jb: bad numeric arg " + n);
        return BigInt(n);
    }
    if (n !== null && typeof n === "object" && typeof n.low === "number") {
        return ((BigInt(n.hi >>> 0) << 32n) | BigInt(n.low >>> 0)) & Y2JB_MASK64;
    }
    throw new Error("y2jb: bad syscall arg");
}

// int64 shim with {low, hi, backing, add32} matching what bagagwa.js needs:
// .low/.hi words, add32() with carry + backing slicing, kernel-ptr checks.
function y2jb_i64(lo, hi) {
    const o = {
        low: (lo >>> 0),
        hi: (hi >>> 0),
        backing: null,
        add32(val) {
            const baseLo = o.low >>> 0;
            const nl = ((baseLo + val) & 0xFFFFFFFF) >>> 0;
            let nh = o.hi >>> 0;
            if (nl < baseLo) nh = (nh + 1) >>> 0;
            const r = y2jb_i64(nl, nh);
            if (o.backing) {
                if (o.backing.byteLength < val) throw new Error("y2jb_i64.add32: overflow");
                r.backing = new Uint8Array(o.backing.buffer, o.backing.byteOffset + val,
                    o.backing.byteLength - val);
            }
            return r;
        },
        sub32(val) {
            const baseLo = o.low >>> 0;
            const nl = ((baseLo - val) & 0xFFFFFFFF) >>> 0;
            let nh = o.hi >>> 0;
            if (nl > baseLo) nh = (nh - 1) >>> 0;
            return y2jb_i64(nl, nh);
        },
        toString(radix) {
            radix = radix || 16;
            const loS = (o.low >>> 0).toString(radix);
            if ((o.hi >>> 0) === 0) return loS;
            const width = radix === 16 ? 8 : Math.ceil(32 / Math.log2(radix));
            let pad = loS;
            while (pad.length < width) pad = "0" + pad;
            return (o.hi >>> 0).toString(radix) + pad;
        }
    };
    return o;
}

// ArrayBuffer -> {remote: BigInt}. Only P.malloc'd buffers are registered;
// unregistered buffers throw loudly instead of corrupting.
const y2jb_memreg = new Map();
function y2jb_findReg(u8) {
    if (!u8 || !u8.buffer) return null;
    return y2jb_memreg.get(u8.buffer) || null;
}

function y2jb_syncOut(u8) {
    const reg = y2jb_findReg(u8);
    if (!reg) throw new Error("y2jb_syncOut: unregistered buffer");
    const base = reg.remote + BigInt(u8.byteOffset);
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    let i = 0;
    for (; i + 8 <= u8.byteLength; i += 8) write64(base + BigInt(i), dv.getBigUint64(i, true));
    for (; i < u8.byteLength; i++) write8(base + BigInt(i), u8[i]);
}

function y2jb_syncIn(u8) {
    const reg = y2jb_findReg(u8);
    if (!reg) throw new Error("y2jb_syncIn: unregistered buffer");
    const base = reg.remote + BigInt(u8.byteOffset);
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    let i = 0;
    for (; i + 8 <= u8.byteLength; i += 8) dv.setBigUint64(i, read64(base + BigInt(i)), true);
    for (; i < u8.byteLength; i++) u8[i] = Number(read8(base + BigInt(i))) & 0xFF;
}

// Prefer runtime SYSCALL[name] when present, else raw FreeBSD number.
// NOTE: pipe -> raw PIPE2 (0x2AF) always; runtime "pipe" is the legacy one.
const Y2JB_NUM2NAME = {
    0x003: "read", 0x004: "write", 0x006: "close", 0x014: "getpid",
    0x018: "getuid", 0x05C: "fcntl", 0x036: "ioctl", 0x1DD: "mmap"
};
function y2jb_resolve(num) {
    const nm = Y2JB_NUM2NAME[num];
    if (nm && typeof SYSCALL !== "undefined" && SYSCALL && SYSCALL[nm] !== undefined) {
        const v = SYSCALL[nm];
        return (typeof v === "bigint") ? v : BigInt(v);
    }
    return BigInt(num);
}

async function y2jb_sys(P, num, ...args) {
    if (P.syscalls[num] === undefined)
        throw new Error("sys: no stub 0x" + num.toString(16));
    while (args.length < 6) args.push(0);
    const conv = [];
    const backed = [];
    for (const a of args.slice(0, 6)) {
        if (typeof a === "bigint") { conv.push(a & Y2JB_MASK64); continue; }
        if (typeof a === "number") { conv.push(y2jb_toBig(a)); continue; }
        if (a !== null && typeof a === "object" && a.backing) {
            const reg = y2jb_findReg(a.backing);
            if (!reg) throw new Error("sys: arg backing not registered");
            y2jb_syncOut(a.backing);
            conv.push((reg.remote + BigInt(a.backing.byteOffset)) & Y2JB_MASK64);
            backed.push(a.backing);
            continue;
        }
        conv.push(y2jb_toBig(a)); // int64-shim immediates
    }
    let raw = await syscall(y2jb_resolve(num), conv[0], conv[1], conv[2], conv[3], conv[4], conv[5]);
    raw = (typeof raw === "bigint") ? raw : BigInt(Math.trunc(Number(raw)));
    for (const u8 of backed) y2jb_syncIn(u8);
    const failed = (raw === Y2JB_MASK64); // FreeBSD-raw: u64 -1, never valid here
    const s32 = Number(BigInt.asIntN(32, raw & 0xFFFFFFFFn));
    return {
        raw, s32, failed,
        hex: "0x" + (raw & Y2JB_MASK64).toString(16),
        errText: failed ? "EFAILED" : "ok"
    };
}

async function y2jb_sleep(ms) {
    if (typeof setTimeout === "function") {
        await new Promise((res) => setTimeout(res, ms));
        return;
    }
    const ts = malloc(16);
    write64(ts, BigInt(Math.floor(ms / 1000)));
    write64(ts + 8n, BigInt((ms % 1000) * 1000000));
    await syscall(0xF0n, ts, 0n);
}

function y2jb_make_P() {
    const P = {
        nogc: [],
        gadgets: {},
        syscalls: {},
        malloc(dwords) {
            const bytes = dwords * 4;
            const remote = malloc(bytes); // Y2JB global, sync, BigInt address
            if (typeof remote !== "bigint") throw new Error("y2jb malloc did not return bigint");
            const buf = new ArrayBuffer(bytes);
            const backing = new Uint8Array(buf);
            y2jb_memreg.set(buf, { remote });
            P.nogc.push(backing);
            for (let off = 0; off + 8 <= bytes; off += 8) write64(remote + BigInt(off), 0n);
            for (let off = bytes - (bytes % 8); off < bytes; off++) write8(remote + BigInt(off), 0);
            const ptr = y2jb_i64(Number(remote & 0xFFFFFFFFn), Number((remote >> 32n) & 0xFFFFFFFFn));
            ptr.backing = backing;
            return ptr;
        }
    };
    const ALL_NUMS = [0x29E, 0x29C, 0x295, 0x297, 0x296, 0x298, 0x299, 0x29A, 0x29D, 0x2B0,
        0x225, 0x226, 0x227, 0x228, 0x229, 0x22A, 0x22B, 0x22C, 0x2D7,
        0x2AF, 0x003, 0x004, 0x006, 0x014, 0x018, 0x061, 0x069, 0x076,
        0x1DD, 0x049, 0x0F0, 0x14B, 0x16A, 0x05C, 0x036, 0x017, 0x029];
    for (const n of ALL_NUMS) P.syscalls[n] = true;
    return P;
}

function y2jb_make_context() {
    const P = y2jb_make_P();
    const state = { syscallsIssued: new Set(), fdOpen: new Set(), cleanupFailed: "" };
    const note = (s) => { try { log("[bgw] " + s); } catch (e) {} };
    return {
        P,
        chain: null,
        i64: y2jb_i64,
        sys: (num, ...a) => y2jb_sys(P, num, ...a),
        runChain: async () => {},
        mem: () => { throw new Error("mem() unused in Y2JB mode"); },
        sleep: y2jb_sleep,
        note,
        track: (fd) => { state.fdOpen.add(fd); },
        untrack: (fd) => { state.fdOpen.delete(fd); },
        state,
        driver: { core: 5, origMaskBytes: null, coreWhy: "y2jb" },
        flushMark: (t, d) => { try { log("[bgw:" + t + "] " + d); } catch (e) {} },
        queueEvent: (t, d) => { try { log("[bgw-ev:" + t + "] " + d); } catch (e) {} }
    };
}
