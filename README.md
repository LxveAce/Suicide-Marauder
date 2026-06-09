# Suicide Marauder

> ## ⚠️ OWNER-ONLY · DEFENSIVE · ANTI-FORENSIC ("DURESS") LAYER
>
> This is a **defensive** add-on for an [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder)
> **that you own**, to protect **your own** data against device theft, loss, or coercion — the same
> category as Kali's LUKS Nuke, GrapheneOS's duress PIN, and BusKill.
>
> It is **NOT** a tool for destroying evidence to obstruct a lawful investigation. Doing so is a
> crime in most jurisdictions (e.g. US 18 U.S.C. §1519). **You are responsible for lawful use.**
>
> **Before you flash, arm, or test anything, read:**
> **[`docs/SAFETY.md`](docs/SAFETY.md) · [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) · [`docs/SPEC.md`](docs/SPEC.md)**
>
> The board can **permanently and irrecoverably destroy data — by design.** A real (non–`SAFE_MODE`)
> brick build is not reversible. Build and test in **`SUICIDE_SAFE_MODE`** first, always.

---

## Status

| | |
|---|---|
| **Maturity** | **Implemented + SAFE_MODE hardware-validated.** The gate (password verify, 2-fail wipe, arming, NVS config, simulated wipe) was validated on a classic ESP32-D0WD in `SUICIDE_SAFE_MODE` with **zero real erases** — full log in [`docs/HARDWARE-TEST.md`](docs/HARDWARE-TEST.md). The interface contract ([`docs/SPEC.md`](docs/SPEC.md)) is frozen. |
| **Brick primitive** | **UNVERIFIED.** The Stage-3 self-erase of the running app/boot-chain has not been proven on hardware — see [`docs/SPIKE-PLAN.md`](docs/SPIKE-PLAN.md). It is implemented but **guarded behind `SUICIDE_SAFE_MODE`**, and CI never produces a live-brick build. |
| **Default tier** | **T1** (no Secure Boot / Flash Encryption — reflashable; data-wipe only). **T2** (Secure Boot v2 + Flash Encryption, true unrecoverable brick) is opt-in and **IRREVERSIBLE** at the eFuse level. |
| **Default variant** | **FORK** (works on every flash size incl. 4 MB). **GUARDIAN** is documented + partition-templated for 8 MB+ (16 MB preferred). |

---

## What it does

A boot-time **gate** (`BootGate::run()`) runs *before* Marauder's normal UI loads. On a board that
has been **provisioned** (a password was set) **and master-armed**, it enforces a duress policy:

- **Password gate** — the operator must enter the correct password (over USB serial by default, or
  the board's own touch / joystick / QWERTY / button input) before Marauder boots. The plaintext
  password is **never stored or logged** — only a salted PBKDF2-HMAC-SHA256 hash lives on the device.
- **2-fail wipe** — after `max_att` wrong attempts (**default 2**), the gate triggers a best-effort
  secure erase of the internal flash partitions, the SD card, and — only if `brick` is set — the
  boot chain itself. The attempt counter is persisted **before** responding, so a power-cycle mid-
  attempt cannot reset it.
- **Dead-man switch** — a hardware arming line (a GPIO). In its **armed position** the (intact)
  switch drives the pin to its active level; a **cut, unplugged, or floating** wire reads
  NOT-ARMED. When the device is armed and in dead-man mode, booting without the switch in the armed
  position is itself a trigger — tamper/removal becomes a wipe.

**Three independent conditions must all be true before any wipe is even possible** (see
[`docs/SAFETY.md`](docs/SAFETY.md)):

1. **Provisioned** — a Suicide build *and* a password is set. A plain Marauder, or an unprovisioned
   Suicide build, returns `GATE_PASS` immediately and **can never wipe**.
2. **Master-armed** — the `armed` flag in `guardcfg` NVS is `1`. **Default is `0` (DISARMED).**
3. A **trigger** fires — `max_att` wrong passwords, or the dead-man line is not in its armed
   position.

> **A correct password always boots and never wipes.** An unprovisioned or master-disarmed board is
> *physically incapable* of wiping. Undervoltage / low-battery boot is treated as **DISARMED**
> (reliability-first).

---

## Variants and tiers

### FORK *(default — all flash sizes, including 4 MB)*
The gate is compiled **into** a fork of ESP32Marauder and called early from `setup()`, reusing
Marauder's own display / keyboard / SD drivers. Self-destruct = the running app erases every other
partition, the SD, then (optionally) its own boot chain. See
[`firmware/integration/INTEGRATION.md`](firmware/integration/INTEGRATION.md) for the exact hook
point (anchored on `display_obj.RunSetup()` / `settings_obj.begin()`, not line numbers).

### GUARDIAN *(optional hardening — 8 MB+ only, 16 MB preferred)*
A tiny **factory** app gates, then jumps (`esp_ota_set_boot_partition(ota_0)` + `esp_restart()`)
into an **unmodified** Marauder in `ota_0`. Cleaner GPL boundary and cleaner brick. Does not fit in
4 MB.

### T1 vs T2
- **T1 (default)** — `brick=0`, no Secure Boot / Flash Encryption. The board is data-wiped but
  **reflashable**. Good for dev/demo and most threat models.
- **T2 (opt-in, IRREVERSIBLE)** — Secure Boot v2 + Flash Encryption release mode + `brick=1`. The
  gate cannot be reflashed past and the erased ciphertext is meaningless. eFuse burns are permanent.

---

## Quickstart (pointers)

1. **Read the safety docs first** — [`docs/SAFETY.md`](docs/SAFETY.md),
   [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).
2. **Understand the contract** — [`docs/SPEC.md`](docs/SPEC.md) is the single source of truth for
   names, NVS keys, offsets, build flags, and the state machine.
3. **Build in SAFE MODE** — `scripts/build.ps1` (Windows) or `scripts/build.sh` (Linux/macOS),
   which default to `SUICIDE_SAFE_MODE=1`. Example:
   ```sh
   ./scripts/build.sh --board esp32 --variant fork --tier T1 --safe-mode
   ```
4. **Provision a device** — `host/provision.py` (password via stdin/getpass, **never argv**)
   produces a `guardcfg.bin`, a blank `otadata.bin`, and a `bundle.json` manifest.
5. **Flash** — either via the CI per-board bundle artifacts, or through the
   [headless-marauder-gui](https://github.com/LxveAce/headless-marauder-gui) flasher integration
   (see [`flasher-integration/PLAN.md`](flasher-integration/PLAN.md)).

---

## Layout

```
Suicide-Marauder/
├── README.md                      ← you are here
├── .gitignore
├── .github/
│   └── workflows/
│       └── build.yml              ← CI matrix → per-board SAFE_MODE suicide bundles
├── docs/
│   ├── SPEC.md                    ← canonical interface contract (source of truth)
│   ├── SAFETY.md                  ← read before flashing / arming / testing
│   ├── THREAT-MODEL.md
│   ├── RESEARCH-DIGEST.md         ← grounded detail + citations
│   ├── SPIKE-PLAN.md              ← sacrificial-board plan for the UNVERIFIED brick
│   ├── HARDWARE-TEST.md           ← SAFE_MODE validation log (classic ESP32)
│   └── LICENSING.md               ← GPL/LGPL distribution notes
├── firmware/
│   ├── bootgate/                  ← gate headers + impl
│   │   ├── GateConfig.h           ← guardcfg NVS schema (canonical)
│   │   ├── BootGate.h             ← boot-gate state machine
│   │   ├── ArmingSwitch.h         ← dead-man line reader
│   │   ├── SelfDestruct.h         ← best-effort secure erase (Stage-3 UNVERIFIED)
│   │   └── GateCrypto.h           ← PBKDF2-HMAC-SHA256 verify
│   ├── partitions/                ← suicide_4MB.csv / suicide_16MB.csv / guardian_16MB.csv
│   ├── integration/
│   │   └── INTEGRATION.md         ← where to insert BootGate::run() in ESP32Marauder.ino
│   └── test_harness/              ← SAFE_MODE bench (validated on real hardware)
├── host/
│   └── provision.py               ← builds guardcfg.bin + bundle.json (no plaintext ever logged)
├── scripts/
│   ├── build.ps1                  ← parameterized build (board/variant/tier/safe-mode)
│   └── build.sh
└── flasher-integration/
    └── PLAN.md                    ← precise plan to add the suicide flash path + tooltips to
                                      headless-marauder-gui
```

---

## Credits & license

Built on **[ESP32Marauder](https://github.com/justcallmekoko/ESP32Marauder)** by
**justcallmekoko** — the display/keyboard/SD drivers and the entire base firmware are theirs. This
project is an additive, owner-only defensive layer on top of that work. ESP32Marauder is MIT;
distribution notes for the LGPL components statically linked in (e.g. ESPAsyncWebServer) are tracked
in [`docs/LICENSING.md`](docs/LICENSING.md) — read it before redistributing any binaries.
