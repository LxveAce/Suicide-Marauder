# Autonomous Night Session — Work Log

**Started:** 2026-06-10 (late). Owner (LxveAce) asleep; agent working autonomously for several hours.
**Mandate:** finish + stress-test the Suicide-Marauder wipe across **every** flashable firmware/board
config; research a **universal (board+firmware-specific) dead-man's switch**; refine the **cyber-controller
dashboard** (cross-comm, optional install password, boot-attack hardening); **organize repos**, update
**profile README + project READMEs + websites**; red-team + loop; **log everything**; save owner choices
for next session; never stop — if blocked, work around it or move to other repo work.

This file is the single source of truth to resume. Append-only sections below; newest status at top.

---

## CONNECTED HARDWARE (this session)
- **COM5** — CYD 2432S028 (classic ESP32, USB-SERIAL CH340). Primary test board. Auto-reset works.
- **COM3** — ESP32-WROOM-32 running **ESP-AT v2.4.0** (Silicon Labs CP210x). Headless. **esptool cannot
  auto-enter download mode** ("Wrong boot mode 0x13") — its adapter lacks the auto-program circuit.
  **OWNER CHOICE NEEDED (logged below): a one-time BOOT-button tap is required to flash COM3, OR confirm
  it has no auto-reset.** Workarounds attempted (manual DTR/RTS classic reset, 10 connect-attempts) all
  failed. Until then COM3 can only be read over serial (running firmware identified), not flashed.

## TOOLCHAIN (set up this session, all under `C:\Users\extra\projects\_smbuild\`)
- `arduino-cli.exe` 1.5.1 (`_smbuild/tools/`), data dir `_smbuild/a15` (`ARDUINO_DIRECTORIES_DATA`).
- esp32 Arduino core **2.0.11** (the version Marauder's CI pins; `package_esp32_dev_index.json`).
- 16 pinned Marauder libs cloned to `_smbuild/libs/` (TFT_eSPI V2.5.34 cyd_micro setup, NimBLE 1.3.8,
  etc. — exact refs from ESP32Marauder/.github/workflows/build_parallel.yml).
- platform.txt patched with `-zmuldefs` (Marauder CI requirement for core 2.0.11).
- ESP32Marauder source cloned to `_smbuild/.../ESP32Marauder` → actually `projects/ESP32Marauder`
  (justcallmekoko master, v1.12.2). Suicide gate injected into `esp32_marauder/` (bootgate flat-copied,
  `.ino` patched: includes + `if (suicide::BootGate::run()!=GATE_PASS) esp_restart();` before
  `settings_obj.begin()`; `partitions.csv` = suicide_4MB.csv).
- Build cmd (CYD touch): `arduino-cli compile --fqbn esp32:esp32:d32:PartitionScheme=min_spiffs
  --libraries _smbuild/libs --build-property "compiler.cpp.extra_flags=-DMARAUDER_CYD_MICRO -DSUICIDE_FORK
  -DGATE_INPUT_TOUCH -DSUICIDE_HAVE_TOUCH_KEYBOARD_OBJ -DARMING_PIN=27 -DARMING_ACTIVE_LEVEL=1
  -DARMING_PULL=2" --build-path _smbuild/build_live ESP32Marauder/esp32_marauder`. SAFE build adds
  `-DSUICIDE_SAFE_MODE`; live wipe omits it.
- Flash: core esptool 4.5.1 at `_smbuild/a15/packages/esp32/tools/esptool_py/4.5.1/esptool.exe`,
  `--flash_mode dio --flash_freq 40m`, regions 0x1000 bootloader / 0x8000 partitions / 0xe000 boot_app0
  (`.../2.0.11/tools/partitions/boot_app0.bin`) / 0x10000 app / 0x1F0000 guardcfg.
- Provision guardcfg: `_smbuild/provision_*.py` call `Suicide-Marauder/host/provision.build_bundle`.
- Test helpers: `_smbuild/trigger_capture.py <port> <secs>` (reset→boot→capture serial),
  `_smbuild/gate_probe*.py`.

---

## MAJOR RESULT (verified): forensic obliteration WORKS on the CYD (classic ESP32)
The live-wipe build, triggered via the dead-man path (armed=1, deadman=1, no arming switch on GPIO27),
**obliterated the entire flash**, verified by esptool read-back — ALL regions 0xFF:
`bootloader@0x1000, partition table@0x8000, app(Marauder) 0x10000..0x1F0000 (header+mid+end),
guardcfg@0x1F0000`. Board now boot-loops in the indestructible mask ROM ("invalid header: 0xffffffff")
— **no firmware, no Marauder, no logs, no partition table (the 'guardcfg' tell is gone), nothing
bootable.** The forensic random-overwrite pass runs on the app before the final erase. Recoverable only
by an owner reflash over UART (mask ROM survives) — exactly the design intent (T1, no eFuse burn).

### The hard part that was solved (self-erasing the running app on stock arduino-esp32)
`CONFIG_SPI_FLASH_DANGEROUS_WRITE_ABORTS=y` in core 2.0.11: `esp_flash_erase_region()` abort()s on the
protected boot chain AND on the running app region. The fix (in `firmware/bootgate/SelfDestruct.cpp`
`brickBootChain`, ESP32 path): erase the running app FIRST (it's gone even if a later step fails), via
the **ROM SPI driver** (`esp_rom_spiflash_unlock/erase_sector/write`) inside the IDF flash-only critical
section `spi_flash_disable_interrupts_caches_and_other_cpu()` (declared `extern` — not in a public
header but exported by libspi_flash.a; it disables IRQs + stalls the other core + disables the cache the
*correct* idle-then-clear way — my manual `Cache_Read_Disable` wedged SPI0/SPI1 arbitration). Also
disable RTC + TG0/TG1 watchdogs (register writes) so the multi-second erase isn't reset mid-wipe. Reset
via RTC_CNTL SW_SYS_RST (esp_restart lives in the now-erased app). Debugged with direct-UART markers
(`brickMark`, IRAM-safe) because arduino suppresses ESP_LOG.

**`wipeInternal` (data partitions) already worked** via esp_partition (spiffs/nvs/coredump/guardcfg
erased + overwritten). Only the running-app + boot-chain self-erase needed the ROM bypass.

---

## OPEN BUGS / TODO (firmware)
1. **SD wipe aborts on no-card** (`wipeSDImpl` → `sdmmc_card_init`, SelfDestruct.cpp:~335). On a board
   with `wipe_sd=1` and no card / SPI-only SD, the SDMMC raw path abort()s instead of failing safe.
   Workaround used for the obliteration test: `wipe_sd=0`. FIX NEEDED: guard the SDMMC raw attempt /
   detect card via SD.h first / skip gracefully. (CYD has an SD slot but no card was inserted.)
2. **Debug `brickMark` UART markers** still in `brickBootChain` — REMOVE for the production build (a
   wiping board should emit nothing on serial). Keep only for bring-up.
3. **Per-chip brick** currently ESP32-only (`CONFIG_IDF_TARGET_ESP32`): RTC/TG WDT + RTC_CNTL reset +
   ROM headers are ESP32 register addresses. S2/S3/C3/C6 need their own addresses + `esp32sX/rom/...`.
   Non-ESP32 falls back to the esp_flash path (works only on DANGEROUS_WRITE_ALLOWED builds).
4. **Other chips/boards untested** (only the CYD classic-ESP32 path is hardware-proven).

## OWNER CHOICES TO MAKE (next session — do not block on these)
- **C1 — COM3 headless board:** needs a one-time BOOT-button tap to enter download mode (no auto-reset),
  OR confirm whether it has an auto-program circuit / which pins. Until then it can't be flashed headless.
- **C2 — T2 (eFuse) tier:** the obliteration above is **T1** (reflashable over UART — recoverable). A true
  "unrecoverable by forensic experts even with chip access" posture needs Secure Boot v2 + Flash
  Encryption + UART-download-disable eFuses (IRREVERSIBLE). Confirm before any eFuse burn. NOT done.
- **C3 — dashboard install password:** opt-in at install — confirm desired default (on/off) + reset path.

---

## ACTION LOG (append-only, newest last)
- Set up arduino-cli + core 2.0.11 + 16 pinned libs + Marauder source + suicide integration. Built CYD
  SAFE touch firmware — owner confirmed on-device the keypad/unlock/error all work.
- Built live-wipe CYD firmware. Diagnosed two abort()s via addr2line: (a) wipeSD no-card abort,
  (b) running-app esp_flash erase abort. Rewrote `brickBootChain` to the ROM-bypass self-brick.
- Marker-debugged the brick hang: `Cache_Read_Disable` wedged the chip; switched to the IDF
  `spi_flash_disable_interrupts_caches_and_other_cpu()`. **Full obliteration verified (all 0xFF).**
- Added TG0/TG1 watchdog disable to the brick (RTC WDT alone wasn't enough — saw TG0WDT_SYS_RESET).
  Rebuild in progress to confirm a clean single-pass wipe.
