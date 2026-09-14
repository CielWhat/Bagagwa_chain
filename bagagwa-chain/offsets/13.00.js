// 13.00 -- user-provided offsets from newer slopkit (works up to 13.60).
// Source JSON for 13.00:
// {"hc":["0x56a58","0x56ca0","0x57ce8"],"gd":"0x1d6fa","nt":"0x48b0",
//  "gps":"0x3352238","gpe":"0x1b860","cls":"0x3352228","cle":"0x274e0",
//  "ers":"0x3352230","ere":"0xf7d0"}
//
// MAPPING STATUS (this repo's slopkit_ref loader expects the OFFSET_* /
// wk_gadgetmap / syscall_map names from 12.00.js):
// - hc -> OFFSET_wk_host_constructor_candidates : CONFIDENT (same shape as 12.00.js:5)
// - nt 0x48b0 matches 12.00 OFFSET_lk_sceKernelSendNotificationRequest (0x48B0)
//   -> stored as OFFSET_lk_sceKernelSendNotificationRequest, TENTATIVE.
// - gd/gps/gpe/cls/cle/ers/ere: UNMAPPED. This old loader does not consume
//   these keys. They are preserved below as FW13_00_RAW so a newer loader
//   that reads them keeps working, but they are NOT wired into ROP.
// - wk_gadgetmap / syscall_map / OFFSET_lk_* / OFFSET_lc_* / OFFSET_KERNEL_*
//   are intentionally LEFT EMPTY. Do NOT copy 12.00 values here: wrong
//   gadgets/syscalls will crash/panic. Fill from the newer slopkit that
//   supplied the JSON, then extend main.js supportedFirmwares.
// This file FAILS CLOSED in old main.js ("offset file empty") by design.

// host-constructor candidates: webkitBase = nativeCtorAddr - hc
const OFFSET_wk_host_constructor_candidates = [0x56a58, 0x56ca0, 0x57ce8];

// Tentative: notification request export (verify against newer slopkit loader).
const OFFSET_lk_sceKernelSendNotificationRequest = 0x48b0;

// Raw user values, preserved verbatim for the newer loader.
const FW13_00_RAW = {
  hc: [0x56a58, 0x56ca0, 0x57ce8],
  gd: 0x1d6fa,
  nt: 0x48b0,
  gps: 0x3352238,
  gpe: 0x1b860,
  cls: 0x3352228,
  cle: 0x274e0,
  ers: 0x3352230,
  ere: 0xf7d0,
};

// Aliases under short names in case the newer loader reads globals directly.
const FW13_00_GD = FW13_00_RAW.gd;
const FW13_00_NT = FW13_00_RAW.nt;
const FW13_00_GPS = FW13_00_RAW.gps;
const FW13_00_GPE = FW13_00_RAW.gpe;
const FW13_00_CLS = FW13_00_RAW.cls;
const FW13_00_CLE = FW13_00_RAW.cle;
const FW13_00_ERS = FW13_00_RAW.ers;
const FW13_00_ERE = FW13_00_RAW.ere;

// Intentionally empty: fill from newer slopkit before use with old main.js.
let wk_gadgetmap = {};
let syscall_map = {};
