// GateConfig.cpp — read the boot-gate config + runtime counter from the `guardcfg` NVS partition.
//
// Canonical schema: docs/SPEC.md §4. Namespaces `sgate` (config) and `sgate_rt` (runtime counter)
// are kept separate so config can be rewritten by the host without resetting the attempt counter.
//
// FAIL-SAFE: a missing `pwhash` blob (or any NVS failure that leaves us without a hash) =>
// provisioned=false, and an unprovisioned device can NEVER wipe (docs/SPEC.md §6 step 2). Defaults
// for every key are the struct defaults declared in GateConfig.h; we only overwrite a field when
// the corresponding key is actually present in NVS.
//
// Owner-only, defensive anti-forensic layer. The plaintext password is never stored — only
// {salt, pwhash, kdf params} live here, and those are read into RAM, never logged.

#include "GateConfig.h"

#include <string.h>

#include "nvs_flash.h"
#include "nvs.h"

namespace suicide {

namespace {

// Canonical guardcfg partition name (SPEC §3). The gate's NVS lives ONLY here.
constexpr const char* GUARDCFG_PART = "guardcfg";

// Ensure the gate's NVS partition is initialized exactly once. Arduino-ESP32's core normally calls
// nvs_flash_init() for the DEFAULT `nvs` partition during startup, but BootGate::run() executes very
// early in setup() and we must not depend on ordering. Re-calling init when already initialized
// returns ESP_OK, so this is safe and idempotent.
//
// SCOPED TO guardcfg (SPEC §4.1): we init the `guardcfg` partition by name and NEVER touch the
// default `nvs` partition here. In particular we must NOT nvs_flash_erase() the default partition —
// that would destroy Marauder's own config on every boot. If `guardcfg` itself is new/corrupt we
// erase+reinit ONLY that partition so a first-boot device still reads cleanly (it will simply find
// no keys => provisioned=false). Marauder's own startup owns the default partition's lifecycle.
void ensureNvsReady() {
  esp_err_t err = nvs_flash_init_partition(GUARDCFG_PART);
  if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    // Truncate + reinit the guardcfg partition ONLY. Never the default `nvs` partition.
    nvs_flash_erase_partition(GUARDCFG_PART);
    nvs_flash_init_partition(GUARDCFG_PART);
  }
}

// Helper: read a u8 key, leaving *dst untouched (default) when the key is absent.
void getU8(nvs_handle_t h, const char* key, uint8_t* dst) {
  uint8_t v;
  if (nvs_get_u8(h, key, &v) == ESP_OK) {
    *dst = v;
  }
}

// Helper: read a u32 key, leaving *dst untouched (default) when the key is absent.
void getU32(nvs_handle_t h, const char* key, uint32_t* dst) {
  uint32_t v;
  if (nvs_get_u32(h, key, &v) == ESP_OK) {
    *dst = v;
  }
}

// Helper: read a fixed-size blob into dst, returning true iff the stored blob is exactly `len`
// bytes and was read successfully. A short/missing/oversized blob is treated as absent (the
// fail-safe direction for pwhash/salt).
bool getBlobExact(nvs_handle_t h, const char* key, uint8_t* dst, size_t len) {
  size_t actual = 0;
  if (nvs_get_blob(h, key, nullptr, &actual) != ESP_OK) {
    return false;
  }
  if (actual != len) {
    return false;
  }
  return nvs_get_blob(h, key, dst, &actual) == ESP_OK && actual == len;
}

}  // namespace

GateConfig GateConfig::load() {
  GateConfig cfg;  // every field starts at its safe default (armed=0, provisioned=false, etc.)

  ensureNvsReady();

  // Open the dedicated `guardcfg` NVS partition by namespace. The partition itself is named
  // "guardcfg" in the table; nvs_open_from_partition lets us key off it explicitly so we never
  // collide with Marauder's own `nvs` partition.
  nvs_handle_t h;
  esp_err_t err = nvs_open_from_partition("guardcfg", NVS_NS_CFG, NVS_READONLY, &h);
  if (err != ESP_OK) {
    // Fall back to the default NVS partition in case the build placed `sgate` there (dev/SAFE
    // builds may not carve a separate guardcfg partition). Still read-only.
    err = nvs_open(NVS_NS_CFG, NVS_READONLY, &h);
  }
  if (err != ESP_OK) {
    // No config namespace at all => brand-new / plain-Marauder board. Unprovisioned: cannot wipe.
    cfg.provisioned = false;
    return cfg;
  }

  // ---- schema version (SPEC §4.1: read and validate; unknown version => NOT provisioned) ----
  // A schema this firmware does not understand must never be allowed to drive a wipe. Treat a
  // missing cfg_ver as the canonical CFG_VERSION (older provisioner that predates the key) but treat
  // any *present-and-different* version as fail-safe non-provisioned.
  uint8_t cfgVer = CFG_VERSION;
  getU8(h, "cfg_ver", &cfgVer);
  bool versionOk = (cfgVer == CFG_VERSION);

  // ---- crypto material (load-bearing for provisioned-ness) ----
  bool haveSalt = getBlobExact(h, "salt", cfg.salt, SALT_LEN);
  bool haveHash = getBlobExact(h, "pwhash", cfg.pwhash, KDF_DKLEN);

  // ---- KDF params ----
  getU32(h, "kdf_iter", &cfg.kdf_iter);
  getU8(h, "kdf_dklen", &cfg.kdf_dklen);

  // ---- arming / policy ----
  getU8(h, "armed", &cfg.armed);
  getU8(h, "arm_pin", &cfg.arm_pin);
  getU8(h, "arm_level", &cfg.arm_level);
  getU8(h, "arm_pull", &cfg.arm_pull);
  getU8(h, "deadman", &cfg.deadman);
  getU8(h, "max_att", &cfg.max_att);

  // SPEC §4.1 safety clamp: max_att >= 1, ALWAYS. A corrupt/hostile stored max_att == 0 would make
  // the very first wrong attempt (att_ct=1 >= 0) trigger a wipe — a foot-gun. Clamp a stored 0 back
  // to the safe compile-time default. (armedFlow additionally refuses to trigger when att_ct == 0.)
  if (cfg.max_att == 0) {
    cfg.max_att = SUICIDE_MAX_ATTEMPTS;
  }

  // ---- wipe scope ----
  getU8(h, "wipe_ota", &cfg.wipe_ota);
  getU8(h, "wipe_nvs", &cfg.wipe_nvs);
  getU8(h, "wipe_spiffs", &cfg.wipe_spiffs);
  getU8(h, "wipe_sd", &cfg.wipe_sd);
  getU8(h, "brick", &cfg.brick);
  getU8(h, "sd_passes", &cfg.sd_passes);

  nvs_close(h);

  // Provisioned ONLY when we have a real hash AND a schema version we understand. Per SPEC §4 the
  // host always writes salt+pwhash together; we additionally require a sane dklen so verify() can't
  // be fooled into a zero-length compare, and a recognized cfg_ver (SPEC §4.1) so an unknown schema
  // can never drive a wipe. A missing/short pwhash or unexpected version => provisioned=false => the
  // gate fails safe (GATE_PASS, no wipe).
  cfg.provisioned = versionOk && haveHash && haveSalt &&
                    cfg.kdf_dklen == KDF_DKLEN && cfg.kdf_iter > 0;

  if (!cfg.provisioned) {
    // Scrub any partially-read crypto material so it can never be used.
    memset(cfg.salt, 0, SALT_LEN);
    memset(cfg.pwhash, 0, KDF_DKLEN);
  }

  return cfg;
}

// ---------------------------------------------------------------------------
// GateRuntime — monotonic wrong-attempt counter in `sgate_rt`.
// ---------------------------------------------------------------------------

namespace {

// Open the runtime namespace (read/write). Mirrors the config-partition fallback logic.
esp_err_t openRuntime(nvs_open_mode_t mode, nvs_handle_t* h) {
  esp_err_t err = nvs_open_from_partition("guardcfg", NVS_NS_RT, mode, h);
  if (err != ESP_OK) {
    err = nvs_open(NVS_NS_RT, mode, h);
  }
  return err;
}

}  // namespace

GateRuntime GateRuntime::load() {
  GateRuntime rt;  // att_ct=0, lock_until=0 by default

  ensureNvsReady();

  nvs_handle_t h;
  if (openRuntime(NVS_READONLY, &h) != ESP_OK) {
    // No runtime namespace yet (first boot) => counter is 0, which is correct.
    return rt;
  }

  getU8(h, "att_ct", &rt.att_ct);
  getU32(h, "lock_until", &rt.lock_until);

  nvs_close(h);
  return rt;
}

void GateRuntime::commitAttempts() {
  // Persist the attempt counter BEFORE responding to a wrong attempt so a power-cycle mid-attempt
  // cannot reset progress toward max_att (docs/SPEC.md §4 / §6). We open read/write here; the
  // partition is writable on the device (the host wrote it but did not lock it). On any failure we
  // simply leave the prior value — the counter is monotonic, so the worst case is one un-counted
  // attempt, never a silent reset.
  ensureNvsReady();

  nvs_handle_t h;
  if (openRuntime(NVS_READWRITE, &h) != ESP_OK) {
    return;
  }

  nvs_set_u8(h, "att_ct", att_ct);
  nvs_set_u32(h, "lock_until", lock_until);
  nvs_commit(h);  // force the write to flash now — do not rely on lazy commit
  nvs_close(h);
}

void GateRuntime::reset() {
  // Called ONLY on a correct password (docs/SPEC.md §6 step 7). Correct always wins: zero the
  // counter and the backoff gate, then persist immediately.
  att_ct = 0;
  lock_until = 0;

  ensureNvsReady();

  nvs_handle_t h;
  if (openRuntime(NVS_READWRITE, &h) != ESP_OK) {
    return;
  }

  nvs_set_u8(h, "att_ct", 0);
  nvs_set_u32(h, "lock_until", 0);
  nvs_commit(h);
  nvs_close(h);
}

}  // namespace suicide
