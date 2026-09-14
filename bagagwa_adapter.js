// bagagwa_adapter.js -- builds the X context that bagagwa.js:141 destructures.
// Driver-agnostic: works with any slopkit-style P/chain once a 13.40 ROP
// profile (wk_gadgetmap + syscall_map) exists. No firmware offsets here.
// Mirrors slopkit_ref/slopkit/bagagwa.html:134-180,298-305.
//
// Usage (inside bagagwa.html module script, after prepare(p)):
//   import { makeBagagwaContext } from "./bagagwa_adapter.js";
//   const ctx = makeBagagwaContext({ P, chain, i64: int64, log });
//   const engine = makeBagagwaEngine(ctx);   // bagagwa.js (global fn)
//   const s0 = await engine.stage0_uaf();
// ... stages 1-5, with validateOff(engine) gating stage5 (see off_validate.js).

const ERRNO_NAMES = {
  1: "EPERM", 2: "ENOENT", 3: "ESRCH", 9: "EBADF", 12: "ENOMEM",
  13: "EACCES", 14: "EFAULT", 17: "EEXIST", 22: "EINVAL", 35: "EAGAIN",
  36: "EINPROGRESS", 38: "ENOSYS", 45: "EOPNOTSUPP", 48: "EADDRINUSE",
  61: "ECONNREFUSED", 78: "ENOSPC",
};

function classifyRaw(raw) {
  // chain.syscall returns int64; kernel errors come back as -errno
  // (hi == 0xFFFFFFFF and signed lo < 0). Same rule as bagagwa.html.
  const lo = raw.low | 0;
  const failed = (raw.hi >>> 0) === 0xFFFFFFFF && lo < 0;
  return { s32: lo, failed };
}

function errTextFor(s32, failed) {
  if (!failed) return "ok";
  const n = (-s32) >>> 0;
  return ERRNO_NAMES[n] || ("errno " + n);
}

export function makeBagagwaContext(opts) {
  const { P, chain, i64 } = opts;
  const log = opts.log || opts.note || (() => {});
  const mark = opts.flushMark || ((_t, _d) => {});
  const queueEvent = opts.queueEvent || ((_t, _d) => {});
  if (!P || typeof P.malloc !== "function")
    throw new Error("adapter: P.malloc missing (need slopkit prepare(p).p)");
  if (!chain || typeof chain.syscall !== "function")
    throw new Error("adapter: chain.syscall missing (need worker_rop chain)");
  if (typeof i64 !== "function")
    throw new Error("adapter: i64 ctor missing (pass int64 from int64.js)");

  const state = { syscallsIssued: new Set(), fdOpen: new Set(), cleanupFailed: "" };
  const track = (fd) => { state.fdOpen.add(fd); };
  const untrack = (fd) => { state.fdOpen.delete(fd); };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const note = (s) => { try { log(s); } catch (_) {} };
  const flushMark = (t, d) => { try { mark(t, d); } catch (_) {} };
  const mem = (n) => {
    const ptr = P.malloc(n, 1);
    return { ptr, u8: ptr.backing };
  };

  async function sys(num, ...args) {
    if (P.syscalls[num] === undefined)
      throw new Error("sys: 0x" + num.toString(16) + " no stub in P.syscalls");
    state.syscallsIssued.add(num);
    // Pad to 6 args like chain.syscall(num,a,b,c,d,e,f) in bagagwa.html.
    const a = args.slice(0, 6);
    while (a.length < 6) a.push(0);
    const raw = await chain.syscall(num, a[0], a[1], a[2], a[3], a[4], a[5]);
    const cl = classifyRaw(raw);
    return {
      raw,
      s32: cl.s32,
      failed: cl.failed,
      hex: "0x" + raw.toString(),
      errText: errTextFor(cl.s32, cl.failed),
    };
  }

  async function runChain() { await chain.run(); }

  const driver = { core: 5, origMaskBytes: null, coreWhy: "bagagwa-adapter" };

  return {
    P, chain, i64, sys, runChain, mem, sleep, note,
    track, untrack, state, driver, flushMark, queueEvent,
  };
}

export { classifyRaw, errTextFor };
