// GateConfig.h — Suicide Marauder boot-gate configuration (read from `guardcfg` NVS).
//
// Canonical schema: see docs/SPEC.md §4. Names/keys here MUST match the host provisioner
// (host/provision.py) and the partition table (firmware/partitions/*.csv) byte-for-byte.
//
// Owner-only, defensive anti-forensic layer. A NON-PROVISIONED or MASTER-DISARMED device can
// never wipe (docs/SAFETY.md). Plaintext passwords are NEVER stored — only {salt, pwhash, params}.
#pragma once

#include <Arduino.h>
#include <stdint.h>

namespace suicide {

// ---- NVS namespaces / keys (canonical — do not rename) ----
static constexpr const char* NVS_NS_CFG = "sgate";     // config
static constexpr const char* NVS_NS_RT  = "sgate_rt";  // runtime counter (kept separate)

// ---- defaults (compile-time fallback only; real values live in guardcfg NVS) ----
#ifndef ARMING_PIN
#define ARMING_PIN 27            // classic ESP32 default; never a strapping pin (SPEC §7)
#endif
#ifndef ARMING_ACTIVE_LEVEL
#define ARMING_ACTIVE_LEVEL 1    // armed = HIGH (intact switch drives it; floating reads LOW)
#endif
#ifndef ARMING_PULL
#define ARMING_PULL 2            // 0=none 1=pullup 2=pulldown
#endif
#ifndef SUICIDE_MAX_ATTEMPTS
#define SUICIDE_MAX_ATTEMPTS 2   // user spec: 2 wrong attempts -> wipe (when ARMED)
#endif
#ifndef SUICIDE_KDF_ITER
#define SUICIDE_KDF_ITER 150000u
#endif

static constexpr uint8_t  KDF_DKLEN   = 32;
static constexpr uint8_t  SALT_LEN    = 16;
static constexpr uint8_t  CFG_VERSION = 1;

struct GateConfig {
  bool     provisioned = false;          // true iff a pwhash exists in NVS

  uint8_t  salt[SALT_LEN]   = {0};
  uint8_t  pwhash[KDF_DKLEN] = {0};
  uint32_t kdf_iter = SUICIDE_KDF_ITER;
  uint8_t  kdf_dklen = KDF_DKLEN;

  uint8_t  armed   = 0;                  // MASTER ARM (0=DISARMED safe default, 1=ARMED)
  uint8_t  arm_pin = ARMING_PIN;
  uint8_t  arm_level = ARMING_ACTIVE_LEVEL;
  uint8_t  arm_pull  = ARMING_PULL;
  uint8_t  deadman   = 1;                // 1: not-armed line wipes; 0: line only keeps locked
  uint8_t  max_att   = SUICIDE_MAX_ATTEMPTS;

  uint8_t  wipe_ota = 1, wipe_nvs = 1, wipe_spiffs = 1, wipe_sd = 1;
  uint8_t  brick = 0;                    // T1 default 0; T2 default 1 (SPEC §8)
  uint8_t  sd_passes = 1;

  // Load from `sgate` NVS namespace. Missing pwhash => provisioned=false (cannot wipe).
  static GateConfig load();
};

// Runtime monotonic state in `sgate_rt`. Counter survives power cycles; reset only on success.
struct GateRuntime {
  uint8_t  att_ct = 0;
  uint32_t lock_until = 0;               // exponential backoff gate (disarmed mode)

  static GateRuntime load();
  void commitAttempts();                 // persist att_ct BEFORE responding to a wrong attempt
  void reset();                          // att_ct=0 on a correct password
};

} // namespace suicide
