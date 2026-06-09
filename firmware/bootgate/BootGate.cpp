// BootGate.cpp — boot-time gate state machine. docs/SPEC.md §6.
//
// Owner-only, DEFENSIVE anti-forensic ("duress") layer for an ESP32 Marauder the operator owns.
// This file implements ONLY the decision logic; the actual destruction lives in SelfDestruct.cpp
// and is itself guarded by SUICIDE_SAFE_MODE. See docs/SAFETY.md and docs/THREAT-MODEL.md.
//
// Hard invariants (SPEC §6):
//   * UNPROVISIONED  -> GATE_PASS, can never wipe (behaves like plain Marauder).
//   * MASTER-DISARMED (cfg.armed == 0) -> GATE_PASS, physically cannot wipe.
//   * CORRECT password -> reset attempt counter, GATE_PASS, never wipes (always wins).
//   * ARMED + deadman + arming line NOT in armed position -> SelfDestruct(REASON_DEADMAN)
//     BEFORE the password is even requested (a missing/cut switch is terminal).
//   * Wrong-password count reaching max_att (ARMED) -> SelfDestruct(REASON_ATTEMPTS).
//     The attempt counter is committed to NVS BEFORE responding, so a power-cycle mid-attempt
//     cannot reset it.
//   * Explicit host `wipe` over serial -> SelfDestruct(REASON_HOST_WIPE).
//   * Undervoltage / low-battery boot -> treated as DISARMED (reliability-first, SPEC §13).
//
// The plaintext password buffer returned by suicide::Input::getPassword() is zeroized after every
// verify() — never stored, never logged.

#include "BootGate.h"

#include "GateConfig.h"
#include "ArmingSwitch.h"
#include "GateCrypto.h"
#include "SelfDestruct.h"
#include "GateInput.h"   // suicide::Input — owned by fw-input, selected by one GATE_INPUT_* flag

#include <Arduino.h>
#include <string.h>

#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)
#include "esp_log.h"
#include "esp_system.h"   // esp_reset_reason()
#include "esp_sleep.h"
// adc battery read is board-specific; we only need a coarse "is the supply too low to trust the
// arming line / NVS write" signal. Provided via the weak hook below.
#endif

namespace suicide {

namespace {

constexpr const char* TAG = "bootgate";

// RAM hygiene (SPEC §4.1): scrub the crypto material from the stack copy of GateConfig before
// Marauder continues. The salted hash is low-sensitivity, but the posture is "never retained".
// volatile writes prevent the compiler from eliding the wipe of soon-dead stack memory.
void scrubConfigSecrets(GateConfig& cfg) {
  volatile uint8_t* h = reinterpret_cast<volatile uint8_t*>(cfg.pwhash);
  for (size_t i = 0; i < sizeof(cfg.pwhash); ++i) h[i] = 0;
  volatile uint8_t* s = reinterpret_cast<volatile uint8_t*>(cfg.salt);
  for (size_t i = 0; i < sizeof(cfg.salt); ++i) s[i] = 0;
}

// ---------------------------------------------------------------------------------------------
// Undervoltage detection (SPEC §13: undervoltage boot => treat as DISARMED, reliability-first).
//
// We deliberately FAIL TOWARD DISARMED (never wipe) when the supply is questionable: a brown-out
// boot is far more likely a flaky battery/USB than a genuine duress event, and wiping on a flaky
// rail risks a half-completed erase. A board package can override gateSupplyIsLow() (declared weak)
// with a real fuel-gauge / ADC reading. Default: only a hardware BROWNOUT reset counts as "low".
// ---------------------------------------------------------------------------------------------
bool defaultSupplyIsLow() {
#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)
  // A brownout reset is the one reset cause that unambiguously means the rail sagged below the
  // detector threshold on the previous power event. Treat that boot as untrusted => DISARMED.
  esp_reset_reason_t r = esp_reset_reason();
  if (r == ESP_RST_BROWNOUT) {
    return true;
  }
#endif
  return false;
}

}  // namespace

// Weak hook: board support packages may provide a real undervoltage measurement (fuel gauge / ADC
// divider). If none is linked, defaultSupplyIsLow() is used.
__attribute__((weak)) bool gateSupplyIsLow() { return defaultSupplyIsLow(); }

// ---------------------------------------------------------------------------------------------
// Re-prompt pacing for the ARMED password loop.
//
// ARMED backoff is intentionally HARD and local — there is no host counter reset path here (SPEC
// §6: "armed: hard, no host reset"). It is a fixed short delay only to debounce a held key / serial
// flood; it must NOT meaningfully extend the window, because the real protection is max_att + the
// power-cycle-safe counter, not a timing wall. Exponential lockout (cfg lock_until) is a
// DISARMED-mode nicety and is not exercised on the armed path.
// ---------------------------------------------------------------------------------------------
void BootGate::backoff(uint32_t attempt) {
  // Linear, capped. attempt is 1-based (the just-failed attempt number).
  uint32_t ms = 500u * attempt;
  if (ms > 3000u) {
    ms = 3000u;
  }
  delay(ms);
}

// ---------------------------------------------------------------------------------------------
// armedFlow — SPEC §6 steps 5-7. Only reached when cfg.provisioned && cfg.armed == 1 and the
// supply is trusted. Returns GATE_PASS on a correct password; otherwise drives SelfDestruct.
// ---------------------------------------------------------------------------------------------
GateResult BootGate::armedFlow(GateConfig& cfg) {
  // Step 6: dead-man pre-check. In dead-man mode a cut/floating/unpowered arming wire reads
  // NOT_ARMED and is terminal BEFORE we ever ask for a password.
  if (cfg.deadman == 1) {
    ArmState line = ArmingSwitch::read(cfg);
    if (line == NOT_ARMED) {
      ESP_LOGW(TAG, "ARMED + deadman: arming line NOT in armed position -> REASON_DEADMAN");
      SelfDestruct::trigger(cfg, REASON_DEADMAN);
      return GATE_TRIGGERED;  // does not return in practice (real, non-SAFE brick)
    }
  }

  // Step 7: password loop. The runtime counter is monotonic and power-cycle-safe.
  GateRuntime rt = GateRuntime::load();

  Input::begin(cfg);

  for (;;) {
    InputResult in = Input::getPassword(cfg);

    if (!in.got) {
      // No input available yet (timeout / driver still waiting). Re-prompt without counting it as
      // a wrong attempt. Defensive: ensure the buffer is clear before looping.
      memset(in.buf, 0, sizeof(in.buf));
      in.len = 0;
      continue;
    }

    // SPEC §6 authenticated host-wipe: a serial `wipe` command sets wipeRequest=true AND carries the
    // password the operator typed at the wipe confirmation prompt (GateInput_serial.cpp). The wipe is
    // deliberate ONLY when that password verifies. An unauthenticated/accidental `wipe\n` (terminal
    // paste, serial noise) yields an empty/garbage secret that fails verify and is counted as a
    // failed attempt — it can NEVER destroy data on its own.
    const bool isWipeRequest = in.wipeRequest;

    // Verify, then IMMEDIATELY zeroize the plaintext regardless of result.
    bool ok = GateCrypto::verify(in.buf, in.len, cfg);
    memset(in.buf, 0, sizeof(in.buf));
    in.len = 0;

    if (ok) {
      if (isWipeRequest) {
        // Authenticated, deliberate panic-wipe (SPEC §6). Correct password + explicit `wipe`.
        ESP_LOGW(TAG, "authenticated host wipe (correct password) -> REASON_HOST_WIPE");
        SelfDestruct::trigger(cfg, REASON_HOST_WIPE);
        return GATE_TRIGGERED;  // does not return in practice
      }
      // Correct password ALWAYS wins: reset the counter and boot. Never wipes.
      rt.reset();
      rt.commitAttempts();
      ESP_LOGI(TAG, "password correct -> GATE_PASS (attempt counter reset)");
      scrubConfigSecrets(cfg);  // RAM hygiene (SPEC §4.1)
      return GATE_PASS;
    }

    // Wrong attempt (including a `wipe` confirmed with the WRONG password — SPEC §6: a wrong wipe
    // password counts as a failed attempt). COMMIT the incremented counter to NVS *before* responding
    // so a power-cycle mid-attempt cannot rewind it (SPEC §4 sgate_rt.att_ct).
    if (rt.att_ct < 0xFF) {
      rt.att_ct += 1;
    }
    rt.commitAttempts();

    // SPEC §4.1 — the counter FAILS CLOSED. If commitAttempts() could not persist att_ct (NVS
    // read-only / full / encryption misconfig), we must NOT keep accepting unlimited guesses. Detect
    // a failed persist by re-reading the runtime namespace and comparing: if the on-flash value did
    // not advance to our in-RAM count, treat the counter as un-persistable, bound the in-RAM count to
    // max_att, and trigger anyway (fail-toward-policy) rather than degrade to unlimited attempts.
    GateRuntime persisted = GateRuntime::load();
    if (persisted.att_ct < rt.att_ct) {
      ESP_LOGE(TAG,
               "att_ct persist FAILED (flash=%u, ram=%u) -> fail-closed: bound to max_att %u and "
               "trigger REASON_ATTEMPTS",
               (unsigned)persisted.att_ct, (unsigned)rt.att_ct, (unsigned)cfg.max_att);
      rt.att_ct = cfg.max_att;  // bound the in-RAM count so we never grant another guess
    }

    // SPEC §4.1 / §6: att_ct == 0 NEVER triggers (no failed attempt => no wipe), regardless of
    // max_att. We only reach the trigger after at least one real wrong attempt (att_ct >= 1).
    if (rt.att_ct != 0 && rt.att_ct >= cfg.max_att) {
      ESP_LOGW(TAG, "wrong-password count %u reached max_att %u -> REASON_ATTEMPTS",
               (unsigned)rt.att_ct, (unsigned)cfg.max_att);
      // Tell the input layer it is locked (cosmetic; trigger does not return in practice).
      Input::notifyLocked(0);
      SelfDestruct::trigger(cfg, REASON_ATTEMPTS);
      return GATE_TRIGGERED;  // does not return in practice
    }

    uint8_t attemptsLeft = (rt.att_ct >= cfg.max_att) ? 0
                                                      : (uint8_t)(cfg.max_att - rt.att_ct);

    // Still attempts remaining: respond, pace, re-prompt. No host reset path on the armed loop.
    Input::notifyWrong(attemptsLeft);
    backoff(rt.att_ct);
  }
}

// ---------------------------------------------------------------------------------------------
// run — SPEC §6 steps 1-7. Called ONCE, early in setup() (FORK: after display_obj.RunSetup() and
// before settings_obj.begin(); see firmware/integration/INTEGRATION.md).
// ---------------------------------------------------------------------------------------------
GateResult BootGate::run() {
  // Step 1: load config from the `sgate` NVS namespace.
  GateConfig cfg = GateConfig::load();

  // Step 2: FAIL-SAFE — an unprovisioned board behaves like plain Marauder and can never wipe.
  if (!cfg.provisioned) {
    ESP_LOGI(TAG, "unprovisioned -> GATE_PASS (cannot wipe)");
    return GATE_PASS;
  }

  // Step 4 (and SPEC §13): MASTER DISARMED — destruct is physically impossible. We also treat an
  // undervoltage/brownout boot as DISARMED for reliability, even on an armed board: a flaky rail
  // must never be allowed to fire the irreversible path or read the arming line. The correct
  // password still boots normally; we simply skip the destruct-capable armed flow.
  if (cfg.armed == 0) {
    ESP_LOGI(TAG, "master DISARMED -> GATE_PASS (cannot wipe)");
    scrubConfigSecrets(cfg);  // RAM hygiene (SPEC §4.1)
    return GATE_PASS;
  }

  if (gateSupplyIsLow()) {
    ESP_LOGW(TAG, "undervoltage boot -> treated as DISARMED -> GATE_PASS (reliability-first)");
    scrubConfigSecrets(cfg);  // RAM hygiene (SPEC §4.1)
    return GATE_PASS;
  }

  // Steps 5-7: master ARMED and supply trusted.
  return armedFlow(cfg);
}

}  // namespace suicide
