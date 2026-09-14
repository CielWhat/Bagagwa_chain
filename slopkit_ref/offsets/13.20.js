// 13.20 -- user-provided offsets from newer slopkit (works up to 13.60).
// Source JSON for 13.20:
// {"hc":["0x56a58","0x56ca0","0x57ce8"],"gd":"0x1d6fa","nt":"0x48b0",
//  "gps":"0x3352238","gpe":"0x1b860","cls":"0x3352228","cle":"0x274e0",
//  "ers":"0x3352230","ere":"0xf7d0"}
// NOTE: identical to 13.00 per supplied JSON.
//
// MAPPING STATUS: see 13.00.js. hc mapped, nt tentative, gd/gps/gpe/cls/cle/
// ers/ere preserved raw. wk_gadgetmap / syscall_map intentionally empty --
// do NOT copy 12.00 values. Fails closed in old main.js by design.

// host-constructor candidates: webkitBase = nativeCtorAddr - hc
const OFFSET_wk_host_constructor_candidates = [0x56a58, 0x56ca0, 0x57ce8];

// Tentative: notification request export (verify against newer slopkit loader).
const OFFSET_lk_sceKernelSendNotificationRequest = 0x48b0;

// Raw user values, preserved verbatim for the newer loader.
const FW13_20_RAW = {
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

const FW13_20_GD = FW13_20_RAW.gd;
const FW13_20_NT = FW13_20_RAW.nt;
const FW13_20_GPS = FW13_20_RAW.gps;
const FW13_20_GPE = FW13_20_RAW.gpe;
const FW13_20_CLS = FW13_20_RAW.cls;
const FW13_20_CLE = FW13_20_RAW.cle;
const FW13_20_ERS = FW13_20_RAW.ers;
const FW13_20_ERE = FW13_20_RAW.ere;

// Intentionally empty: fill from newer slopkit before use with old main.js.
let wk_gadgetmap = {};
let syscall_map = {};
