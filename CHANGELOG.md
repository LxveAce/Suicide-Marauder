# Changelog

All notable changes to Suicide Marauder are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Status:** superseded by [Dead Man's Switch](https://github.com/LxveAce/deadmans-switch);
> kept as a hardware-validated reference under doc-only maintenance. See the README's successor
> notice.

## [Unreleased]

### Added
- Standalone universal dead-man gate (`firmware/guardian/`) — firmware-agnostic, hardware-validated
  full-flash obliteration on a blank ESP32.
- Reusable `build_bundle()` entry point in `host/provision.py` so GUI/programmatic callers (e.g.
  Cyber Controller's Suicide setup) can provision without the interactive `getpass` flow.
- Host-side `pytest` suite (`host/tests/test_provision.py`) + `host/requirements-dev.txt` covering
  partition-offset resolution, password/KDF bounds, the fail-safe arm pairs, the `guardcfg` NVS
  size floor, and the one-`otadata`-seed manifest rule.
- Dead Man's Switch successor notice in the README.

### Changed
- `ci/` reconciled with the now-active `.github/workflows/`: removed the byte-identical duplicate
  `ci/build.yml` and rewrote `ci/README.md` to point at the live workflow.
- Docs: SPEC §1 now documents the fail-closed FORK hook
  (`if (suicide::BootGate::run() != suicide::GATE_PASS) { esp_restart(); }`, matching the README
  and `firmware/integration/INTEGRATION.md`); the `_sha256_file` docstring now notes the flasher
  verify step is a documented plan (`flasher-integration/PLAN.md`), not yet a shipped flasher.
- Host ↔ firmware password parity hardened (reject secrets the firmware would hash differently).
- README refreshed for accuracy + added a Connect/contact section.

### Fixed
- BootGate no longer telegraphs an imminent wipe — `notifyLocked()` fires only on the low-supply
  LOCK path, never before an attempts-triggered wipe.
- Forensic obliteration brick primitive (ROM-SPI bypass), hardware-validated as a full-flash
  obliteration on a CYD.
- 4 MB `guardcfg` partition raised to the ESP-IDF read/write NVS minimum (a smaller partition left
  the gate inactive — `provisioned=false`).
- CYD touch build fixed (both touch defines required).

### Notes
- The firmware reports `SM_FW_VERSION = 1.1.0` over the `SM_INFO` serial command, which is ahead of
  the latest release tag `v1.0.1`. Choosing the canonical version — and whether to cut a matching
  release or formally archive the repo — is a pending owner decision, not yet reconciled here.

## [1.0.1] - 2026-06-10

### Changed
- Forensic wipe: overwrite-then-erase + verify for internal flash.
- GPIO overhaul — SD full-LBA erase, arming documentation, brownout hardening, dashboard hooks.

### Fixed
- Red-team round 3: T2 flash-encryption verify, wipe-resume convergence, factory/scratch coverage,
  and RAM scrub of key material after `GATE_PASS`.

## [1.0.0] - 2026-06-10

First packaged release: owner-only, hardware-validated anti-forensic boot-gate + secure-wipe layer
for an ESP32 Marauder you own.

### Added
- Boot-gate state machine (`BootGate::run()`), PBKDF2-HMAC-SHA256 password gate, dead-man arming,
  and the multi-partition secure-wipe / brick paths.
- Host provisioner (`host/provision.py`) that bakes the per-device `guardcfg` NVS image, a blank
  `otadata` blob, and a flash-bundle manifest (offsets read from the partition CSV, never
  hardcoded).
- Reproducible `SUICIDE_SAFE_MODE` test harness + build scripts; classic-ESP32 hardware validation.
- GitHub Actions workflows for firmware builds and provisioner release packaging.

### Security
- Red-team rounds 1–2: closed a brownout bypass and a `resumeWipe` force-wipe regression; hardened
  the wipe and provisioning paths.

[Unreleased]: https://github.com/LxveAce/Suicide-Marauder/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/LxveAce/Suicide-Marauder/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/LxveAce/Suicide-Marauder/releases/tag/v1.0.0
