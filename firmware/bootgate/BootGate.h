// BootGate.h — the boot-time gate. Call BootGate::run() ONCE, early in setup().
//
// FORK variant hook (docs/SPEC.md §1): in ESP32Marauder.ino, place the call AFTER
// display_obj.RunSetup() and BEFORE settings_obj.begin(). See firmware/integration/INTEGRATION.md.
//
// State machine: docs/SPEC.md §6. Invariants:
//   * unprovisioned OR master-disarmed  -> GATE_PASS, never wipes
//   * correct password                  -> GATE_PASS, resets attempt counter, never wipes
//   * dead-man line not-armed (armed+deadman) -> SelfDestruct before password is even asked
//   * wrong attempts reach max_att (armed)    -> SelfDestruct
#pragma once

#include "GateConfig.h"

namespace suicide {

enum GateResult { GATE_PASS, GATE_TRIGGERED };

enum TriggerReason {
  REASON_NONE = 0,
  REASON_DEADMAN,     // arming line not in armed position (dead-man)
  REASON_ATTEMPTS,    // wrong-password count reached max_att
  REASON_HOST_WIPE,   // explicit `wipe` command over serial (host-assisted)
};

class BootGate {
 public:
  // Runs the full gate. Returns GATE_PASS to let Marauder continue booting.
  // GATE_TRIGGERED is returned only in SAFE_MODE (a real trigger does not return).
  static GateResult run();

 private:
  static GateResult armedFlow(GateConfig& cfg);   // master-armed path (SPEC §6 steps 5-7)
  static void       backoff(uint32_t attempt);    // re-prompt pacing
};

} // namespace suicide
