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
//   * Undervoltage / low-battery boot (ARMED) -> destruct SUPPRESSED but the correct password is
//     STILL required to boot (NO bypass): the dead-man pre-check is skipped and reaching max_att
//     LOCKS/re-prompts forever instead of wiping. A brownout must NEVER cause a wipe (reliability-
//     first, SPEC §13) and must NEVER hand out an unlocked board.
//   * Wipe-in-progress tombstone (sgate_rt.wipe_armed) -> RESUME the interrupted self-destruct on
//     the next boot (an interrupted wipe must finish, SPEC §8) — never a clean PASS over residual data.
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
// armedFlow — SPEC §6 steps 5-7. Reached when cfg.provisioned && cfg.armed == 1.
//
// lowSupply (SPEC §13, brownout-bypass fix): when the supply is questionable (brownout/undervoltage
// boot) destruction is SUPPRESSED but the gate is NOT bypassed. The CORRECT password is STILL
// required to boot — a low rail must never hand an attacker an unlocked board. But because a flaky
// rail must NEVER cause an irreversible wipe (reliability-first), on a low-supply boot we:
//   * SKIP the dead-man pre-check entirely (the ADC/arming-line read is untrustworthy at low V, and
//     a missing switch must not fire the irreversible path on a sagging rail), and
//   * on reaching max_att, LOCK/HALT forever (re-prompt loop, never SelfDestruct) instead of wiping.
// Returns GATE_PASS only on a correct password; otherwise drives SelfDestruct (trusted supply) or
// locks forever (low supply).
// ---------------------------------------------------------------------------------------------
GateResult BootGate::armedFlow(GateConfig& cfg, bool lowSupply) {
  // Step 6: dead-man pre-check. In dead-man mode a cut/floating/unpowered arming wire reads
  // NOT_ARMED and is terminal BEFORE we ever ask for a password.
  // SUPPRESSED on a low-supply boot: do not read the arming line and do not allow a deadman wipe —
  // a brownout must never fire the irreversible path (SPEC §13). The password is still required.
  if (cfg.deadman == 1 && !lowSupply) {
    ArmState line = ArmingSwitch::read(cfg);
    if (line == NOT_ARMED) {
      ESP_LOGW(TAG, "ARMED + deadman: arming line NOT in armed position -> REASON_DEADMAN");
      SelfDestruct::trigger(cfg, REASON_DEADMAN);
      return GATE_TRIGGERED;  // does not return in practice (real, non-SAFE brick)
    }
  } else if (cfg.deadman == 1 && lowSupply) {
    ESP_LOGW(TAG, "low-supply boot: SKIPPING dead-man pre-check (suppress destruct; password still "
                  "required) — reliability-first (SPEC §13)");
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
      if (isWipeRequest && !lowSupply) {
        // Authenticated, deliberate panic-wipe (SPEC §6). Correct password + explicit `wipe`.
        ESP_LOGW(TAG, "authenticated host wipe (correct password) -> REASON_HOST_WIPE");
        SelfDestruct::trigger(cfg, REASON_HOST_WIPE);
        return GATE_TRIGGERED;  // does not return in practice
      }
      if (isWipeRequest && lowSupply) {
        // Brownout-suppression (SPEC §13): even a correct, deliberate host-wipe must not run on a
        // sagging rail (risk of a half-completed erase). The password verified, so we BOOT normally
        // and reset the counter; the owner can re-issue the wipe on a healthy supply.
        ESP_LOGW(TAG, "low-supply boot: authenticated host wipe SUPPRESSED (booting instead; "
                      "re-issue on a healthy supply) — reliability-first (SPEC §13)");
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
      // Tell the input layer it is locked (cosmetic).
      Input::notifyLocked(0);
      if (lowSupply) {
        // Brownout-suppression (SPEC §13): a flaky rail must NEVER cause a wipe. We do NOT
        // SelfDestruct. Instead we LOCK and KEEP RE-PROMPTING forever — the CORRECT password (handled
        // at the top of this loop) is still the only way to boot, so there is no bypass. The persisted
        // att_ct stays at/above max_att, so a later boot on a HEALTHY supply will enforce the real
        // REASON_ATTEMPTS policy. We deliberately fall through to the re-prompt (no return, no
        // trigger) rather than halting hard, so a correct password can still rescue the boot.
        ESP_LOGW(TAG, "low-supply boot: max_att reached -> LOCK, re-prompting forever (NO wipe; "
                      "correct password still boots) — reliability-first (SPEC §13)");
        backoff(rt.att_ct);
        continue;  // re-prompt; never SelfDestruct on a low-supply boot
      }
      ESP_LOGW(TAG, "wrong-password count %u reached max_att %u -> REASON_ATTEMPTS",
               (unsigned)rt.att_ct, (unsigned)cfg.max_att);
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

  // Step 1.5 (SPEC §8 robustness, red-team): RESUME an interrupted wipe. If the wipe-in-progress
  // tombstone (`sgate_rt.wipe_armed`) is set, a previous self-destruct started and was cut short
  // (power loss mid-erase). The board may now read as UNPROVISIONED (its guardcfg was partly
  // erased) — but it must NOT report a clean PASS over residual data. Re-trigger SelfDestruct so the
  // wipe FINISHES. This takes priority over every other branch, including the unprovisioned check
  // below. (A real, interrupted wipe is already past the reliability-first "never initiate on a
  // flaky rail" rule — the data is already partly gone; finishing it is the only safe end state.)
  if (cfg.resumeWipe) {
    ESP_LOGW(TAG, "wipe tombstone set (sgate_rt.wipe_armed=1) -> RESUMING interrupted self-destruct "
                  "(SPEC §8). Will not report a clean PASS over residual data.");
    SelfDestruct::trigger(cfg, REASON_ATTEMPTS);
    return GATE_TRIGGERED;  // does not return in practice on a real wipe
  }

  // Step 2: FAIL-SAFE — an unprovisioned board behaves like plain Marauder and can never wipe.
  if (!cfg.provisioned) {
    ESP_LOGI(TAG, "unprovisioned -> GATE_PASS (cannot wipe)");
    return GATE_PASS;
  }

  // Step 4: MASTER DISARMED — destruct is physically impossible (kept as-is). The correct password
  // is cosmetic here; we simply skip the destruct-capable armed flow.
  if (cfg.armed == 0) {
    ESP_LOGI(TAG, "master DISARMED -> GATE_PASS (cannot wipe)");
    scrubConfigSecrets(cfg);  // RAM hygiene (SPEC §4.1)
    return GATE_PASS;
  }

  // BROWNOUT-BYPASS FIX (SPEC §13, red-team): a low-supply/undervoltage boot must NOT early-return
  // GATE_PASS on an ARMED board — that would boot an armed board with NO password (a full gate
  // bypass). Instead we pass the low-supply state INTO armedFlow, where it ONLY SUPPRESSES
  // destruction (skip dead-man pre-check; lock-and-reprompt forever at max_att instead of wiping).
  // The CORRECT password is STILL required to boot, and a brownout can never cause a wipe.
  const bool lowSupply = gateSupplyIsLow();
  if (lowSupply) {
    ESP_LOGW(TAG, "undervoltage boot on ARMED board: destruct SUPPRESSED but password STILL "
                  "required (no bypass) — reliability-first (SPEC §13)");
  }

  // Steps 5-7: master ARMED. armedFlow honors lowSupply to suppress (never bypass) destruction.
  return armedFlow(cfg, lowSupply);
}

}  // namespace suicide
