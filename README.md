# Suicide Marauder

> **Note:** This project has been succeeded by [Dead Man's Switch](https://github.com/LxveAce/deadmans-switch) — a universal anti-forensic dead-man gate with expanded board support. Suicide Marauder remains available as the original implementation.

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
| **Maturity** | **Implemented + hardware-validated (SAFE_MODE *and* live wipe).** The full gate (password verify, 2-fail wipe, arming, NVS config) was validated on a classic ESP32 in `SUICIDE_SAFE_MODE` ([`docs/HARDWARE-TEST.md`](docs/HARDWARE-TEST.md), zero erases), and the **real, live wipe was then hardware-validated on a CYD 2432S028** (classic ESP32) — see [`docs/NIGHT-SESSION-LOG.md`](docs/NIGHT-SESSION-LOG.md). The interface contract ([`docs/SPEC.md`](docs/SPEC.md)) is the single source of truth. |
| **Brick primitive** | **HARDWARE-VALIDATED on classic ESP32.** A dead-man-triggered live wipe obliterated the *entire* flash — verified by esptool read-back, every region `0xFF`: bootloader, partition table, the full running app, NVS/SPIFFS/logs/coredump, and `guardcfg`, with a forensic random-overwrite pass. The running-app self-erase (the part no Espressif source documents) works on the stock arduino-esp32 core via a **ROM-SPI bypass inside the IDF flash-only critical section** (`spi_flash_disable_interrupts_caches_and_other_cpu`), with RTC + TG0/TG1 watchdogs disabled so the multi-second erase completes in one pass. Currently **ESP32-only**; S2/S3/C3/C6 fall back to the `esp_flash` path and get their per-chip ROM brick next. See [`docs/SPIKE-PLAN.md`](docs/SPIKE-PLAN.md). |
| **Default tier** | **T1** (no Secure Boot / Flash Encryption — reflashable; data-wipe only). **T2** (Secure Boot v2 + Flash Encryption, true unrecoverable brick) is opt-in and **IRREVERSIBLE** at the eFuse level. |
| **Variants** | **FORK** (default — gate compiled into Marauder; works on every flash size incl. 4 MB), **GUARDIAN** (factory + `ota_0` split, 8 MB+, 16 MB preferred), and a **standalone universal gate** (`firmware/guardian/guardian.ino` — firmware-agnostic, hardware-validated on a blank ESP32). |

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
  - **Overwrite-then-erase + verify** — each internal partition optionally takes `flash_passes`
    random overwrite passes (`--flash-passes`), then a final clean erase, then a **raw read-back
    verify** (via `esp_flash_read`, which sees true `0xFF` even on a Flash-Encryption board). A
    single NOR erase is forensically sufficient; the random overwrite is **defense-in-depth only**.
  - **SD full-LBA erase** — when raw sector access is available (SDMMC host, opt-in via
    `-DSUICIDE_SD_SDMMC`), the SD wipe writes zeros to every sector on the card (LBA 0 through last
    sector), bypassing the filesystem for forensic-grade erasure. Falls back to abort-safe
    file-level overwrite + free-space fill when raw access is unavailable or no card is present.
    With `sd_passes >= 2`, a secure-erase pattern writes random data then zeros.
  - **Fast wipe mode** — with `fast_wipe=1`, the SD wipe is skipped entirely and the gate goes
    straight to flash erase + boot brick, completing in seconds instead of minutes. Designed for
    brownout-prone or battery-powered setups.
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
> (reliability-first): destruction is suppressed, but the correct password is still required (no
> bypass).

---

## Variants and tiers

### FORK *(default — all flash sizes, including 4 MB)*
The gate is compiled **into** a fork of ESP32Marauder and called early from `setup()`, reusing
Marauder's own display / keyboard / SD drivers. The integration is **two edits to one file**: an
include, plus a single **fail-closed** call —
`if (suicide::BootGate::run() != suicide::GATE_PASS) { esp_restart(); }` — inserted **after**
`display_obj.RunSetup()` and **before** `settings_obj.begin()`. Self-destruct = the running app
erases every other partition, the SD, then (optionally) its own boot chain. See
[`firmware/integration/INTEGRATION.md`](firmware/integration/INTEGRATION.md) for the exact hook
point (anchored on strings, not line numbers).

### GUARDIAN *(optional hardening — 8 MB+ only, 16 MB preferred)*
A tiny **factory** app gates, then jumps (`esp_ota_set_boot_partition(ota_0)` + `esp_restart()`)
into an **unmodified** Marauder in `ota_0`. Cleaner GPL boundary and cleaner brick. Does not fit in
4 MB.

### Standalone universal gate *(`firmware/guardian/guardian.ino`)*
The boot-gate with **no host firmware** — proof that the Suicide gate is **firmware-agnostic**. It
runs first, gates (password / dead-man / attempt-count), and on PASS hands off to whatever firmware
lives in `ota_0` (Marauder, Bruce, GhostESP, ESP32-DIV, …). A wrong-password / dead-man trigger
runs the same `SelfDestruct` forensic obliteration as the FORK. This is the basis of the universal
dead-man switch and was **hardware-validated on a blank classic ESP32** (a provisioned, armed
build wiped the entire flash on a wrong-password ×2 trigger). See
[`firmware/guardian/README.md`](firmware/guardian/README.md).

### T1 vs T2
- **T1 (default)** — `brick=0`, no Secure Boot / Flash Encryption. The board is data-wiped but
  **reflashable** (over UART by the owner — no eFuse burn). Good for dev/demo and most threat
  models.
- **T2 (opt-in, IRREVERSIBLE)** — Secure Boot v2 + Flash Encryption release mode + `brick=1`. The
  gate cannot be reflashed past and the erased ciphertext is meaningless. eFuse burns are permanent.

---

## Boot-chain brick

The brick stage erases the bootloader, partition table, and the running app region, rendering the
ESP32 non-bootable. This is the primitive that **no Espressif source documents** for a *running*
app — and it is now **hardware-validated on classic ESP32** (CYD 2432S028 and a blank ESP32 via the
standalone Guardian).

How the running-app self-erase works on the stock arduino-esp32 core:

- `esp_flash_erase_region()` `abort()`s under `CONFIG_SPI_FLASH_DANGEROUS_WRITE_ABORTS` on both the
  protected boot chain and the running app slot, so it is bypassed with the **ROM SPI driver**
  (`esp_rom_spiflash_unlock` / `erase_sector` / `write`) inside the IDF flash-only critical section
  `spi_flash_disable_interrupts_caches_and_other_cpu()`.
- The running app is obliterated **first** (gone even if a later step fails), then a forensic
  random-overwrite pass + final erase, then the partition table and 2nd-stage bootloader, then a
  raw `RTC_CNTL` system reset (since `esp_restart` lives in the now-erased app).
- The RTC + TG0/TG1 watchdogs are disabled so the multi-second full-app erase is never reset
  mid-wipe.

**Recovery (T1):** the silicon is undamaged — enter ROM download mode (hold BOOT/GPIO0 during
reset) and re-flash over UART. **T2** closes that with Secure Boot v2 + Flash Encryption and is
irreversible at the eFuse level.

**Scope:** the ROM-SPI brick path is currently **ESP32-only**. S2/S3/C3/C6 use the `esp_flash`
fallback and their per-chip ROM brick is the next item ([`docs/SPIKE-PLAN.md`](docs/SPIKE-PLAN.md)).
Never enable `brick=1` on a non-sacrificial board until you have validated the live path for your
chip class in `SUICIDE_SAFE_MODE` first.

---

## Arming switch wiring

Full wiring guides for each board class are in [`docs/HARDWARE.md`](docs/HARDWARE.md). The key
points:

- **ESP32 Gold boards (GPIO27):** wire an SPDT toggle switch with common to GPIO27, one throw to
  3.3V, and a 10k pull-down resistor from GPIO27 to GND. Switch in ARMED position drives GPIO27
  HIGH; cut/floating/open defaults to LOW = NOT ARMED (fail-safe).
- **ESP32-C5 boards (Grove G2):** wire through the Grove HY2.0-4P connector. The Grove cable
  provides 3.3V and GND, so the switch + pull-down can be wired inline within a modified cable.
- See [`docs/HARDWARE.md`](docs/HARDWARE.md) sections 7-8 for detailed wiring diagrams, parts
  lists, and test procedures for each board class.

---

## Brownout / low-voltage protection

The gate includes multi-layer protection against brownout conditions during wipe:

- **Hardware brownout detection:** a brownout reset on the previous boot flags the current boot as
  low-supply. Destruction is SUPPRESSED but the correct password is STILL REQUIRED (no bypass).
- **ADC-based voltage monitoring (optional):** define `SUPPLY_ADC_PIN` and
  `SUPPLY_ADC_THRESHOLD_MV` at build time for runtime supply voltage checking.
- **Brownout event logging:** every brownout event is logged to NVS and queryable via `SM_INFO`.
- **Priority ordering:** if voltage drops, flash erase (seconds) is prioritized over SD wipe
  (minutes). Use `--fast-wipe 1` during provisioning to skip SD wipe entirely on trigger.
- **Resumable wipe:** an interrupted wipe sets a tombstone and resumes on the next good-power boot,
  bounded by `MAX_WIPE_RESUMES` (a resume forces erase-only and skips the long SD pass so it
  converges instead of looping).

See [`docs/HARDWARE.md`](docs/HARDWARE.md) section 9 and
[`docs/SPEC.md`](docs/SPEC.md) section 13 for details.

---

## Dashboard integration (Cyber Controller)

Suicide Marauder exposes serial commands for remote management by
[Cyber Controller](https://github.com/LxveAce/cyber-controller) or any host tool that speaks
115200-baud serial. Commands are case-insensitive, terminated by CR/LF. Responses are JSON lines
prefixed with `SM>`.

| Command | Description | Auth required? |
|---------|-------------|----------------|
| `SM_STATUS` | Return current state (provisioned, armed, attempt count, tombstone) | No |
| `SM_INFO` | Return firmware version, board type, pin config, SD status, brownout count | No |
| `SM_ARM` | Arm the device (reports: requires re-provisioning from host) | N/A |
| `SM_DISARM <pw>` | Disarm the device (reports: requires re-provisioning from host) | N/A |
| `SM_SET_PASSWORD <old> <new>` | Change password (reports: requires re-provisioning) | N/A |
| `SM_WIPE` | Trigger immediate wipe (redirects to authenticated wipe flow) | Yes (password) |

**Example interaction:**
```
> SM_STATUS
SM>{"cmd":"STATUS","provisioned":true,"armed":1,"deadman":1,"max_att":2,"att_ct":0,"wipe_armed":0,"resume_count":0}

> SM_INFO
SM>{"cmd":"INFO","fw_version":"1.1.0","arm_pin":27,"arm_level":1,"arm_pull":2,"brick":0,"fast_wipe":0,"wipe_sd":1,"wipe_ota":1,"wipe_nvs":1,"wipe_spiffs":1,"sd_passes":1,"kdf_iter":10000,"sd_present":true,"brownout_count":0,"board":"esp32"}
```

Note: `SM_ARM`, `SM_DISARM`, and `SM_SET_PASSWORD` cannot modify the device at runtime because
the armed flag and password hash are baked into the `guardcfg` NVS image at provisioning time.
These commands exist so a controller can discover the limitation and direct the operator to
re-provision. Suicide Marauder is designed to be integrated into Cyber Controller as a **git
submodule**.

---

## Quickstart (pointers)

1. **Read the safety docs first** — [`docs/SAFETY.md`](docs/SAFETY.md),
   [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).
2. **Understand the contract** — [`docs/SPEC.md`](docs/SPEC.md) is the single source of truth for
   names, NVS keys, offsets, build flags, and the state machine.
3. **Build in SAFE MODE** — `scripts/build.ps1` (Windows) or `scripts/build.sh` (Linux/macOS),
   which default to `SUICIDE_SAFE_MODE`. A live-brick build requires explicitly passing
   `--no-safe-mode` **and** acknowledging the unverified live brick (`--allow-live-brick` when
   `brick=1`). Example:
   ```sh
   ./scripts/build.sh --board esp32 --variant fork --tier T1 --input serial
   ```
   Supported `--board` classes: `esp32`, `esp32s2`, `esp32s3`, `esp32c3`, `esp32c6`.
   Supported `--input` adapters: `serial`, `touch`, `mini_kb`, `cardputer`, `buttons`.
4. **Provision a device** — `host/provision.py` (password via stdin/getpass, **never argv**)
   produces a `guardcfg.bin`, a blank `otadata.bin`, and a `bundle.json` manifest. The plaintext
   password is held only in a zeroized buffer; only `{salt, pwhash, kdf params}` reach the device.
   Prebuilt standalone provisioner executables (Windows / macOS / Linux) are attached
   to each [release](https://github.com/LxveAce/Suicide-Marauder/releases).
5. **Flash** — either via the CI per-board SAFE_MODE bundle artifacts, or through the
   [headless-marauder-gui](https://github.com/LxveAce/headless-marauder-gui) flasher integration
   (see [`flasher-integration/PLAN.md`](flasher-integration/PLAN.md)).

---

## Continuous integration

GitHub Actions builds a per-board "suicide bundle" (`app.bin` + `partitions.bin` +
`bootloader.bin` + `boot_app0.bin`) across the FORK/GUARDIAN × T1/T2 × board-class matrix, with the
ESP32 Arduino core pinned. **CI always builds with `SUICIDE_SAFE_MODE`** and never produces a
live-brick build, never burns an eFuse, and never writes a board — `guardcfg.bin`/`otadata` are
per-device and minted locally by `host/provision.py`, never in CI. A separate release workflow
packages the standalone provisioner executables. See
[`.github/workflows/`](.github/workflows/).

---

## Layout

```
Suicide-Marauder/
├── README.md                      ← you are here
├── .github/workflows/             ← SAFE_MODE bundle matrix + provisioner-exe release
├── docs/
│   ├── SPEC.md                    ← canonical interface contract (source of truth)
│   ├── SAFETY.md                  ← read before flashing / arming / testing
│   ├── THREAT-MODEL.md
│   ├── ARCHITECTURE.md
│   ├── HARDWARE.md · HARDWARE-TEST.md   ← wiring guide + hardware validation log
│   ├── PROVISIONING.md
│   ├── RESEARCH-DIGEST.md         ← grounded detail + citations
│   ├── SPIKE-PLAN.md              ← per-chip brick spike plan
│   ├── NIGHT-SESSION-LOG.md       ← live-wipe / brick bring-up log
│   └── LICENSING.md               ← GPL/LGPL distribution notes
├── firmware/
│   ├── bootgate/                  ← gate headers + impl
│   │   ├── GateConfig.*           ← guardcfg NVS schema (canonical)
│   │   ├── BootGate.*             ← boot-gate state machine
│   │   ├── ArmingSwitch.*         ← dead-man line reader
│   │   ├── SelfDestruct.*         ← overwrite-then-erase + read-back verify + brick
│   │   ├── GateCrypto.*           ← PBKDF2-HMAC-SHA256 verify (constant-time compare)
│   │   └── GateInput_*.cpp        ← per-board input adapters (serial/touch/mini/cardputer/buttons)
│   ├── guardian/                  ← standalone universal dead-man gate (firmware-agnostic)
│   ├── partitions/                ← suicide_4MB/8MB/16MB + guardian_16MB CSVs (mandatory scratch)
│   ├── integration/               ← FORK setup() hook + PlatformIO example + .ino patch
│   └── test_harness/              ← SAFE_MODE bench (validated on real hardware)
├── host/
│   ├── provision.py               ← builds guardcfg.bin + bundle.json (no plaintext ever logged)
│   ├── nvs_config.csv.template
│   └── requirements.txt
├── scripts/                       ← parameterized build (board/variant/tier/input) + test-harness build
├── ci/                            ← shared CI build config
└── flasher-integration/
    └── PLAN.md                    ← plan to add the suicide flash path + tooltips to headless-marauder-gui
```

---

## Credits & license

Built on **[ESP32Marauder](https://github.com/justcallmekoko/ESP32Marauder)** by
**justcallmekoko** — the display/keyboard/SD drivers and the entire base firmware are theirs. This
project is an additive, owner-only defensive layer on top of that work. ESP32Marauder is MIT;
distribution notes for the LGPL components statically linked in (e.g. ESPAsyncWebServer) are tracked
in [`docs/LICENSING.md`](docs/LICENSING.md) — read it before redistributing any binaries.

Suicide Marauder is MIT © 2026 LxveAce.

---

## Connect

- **Discord:** [discord.gg/lxveace](https://discord.gg/lxveace) — questions, help, or to talk through this project
- **GitHub:** [@LxveAce](https://github.com/LxveAce)
- **Website:** [lxveace.com](https://lxveace.com)
- **Project site:** [esp32marauder.com](https://esp32marauder.com)