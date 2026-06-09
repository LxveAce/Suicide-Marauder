# THREAT MODEL

## What this protects, and for whom

**Asset:** the data on a single ESP32 Marauder that the operator owns — captured PCAPs, Evil-Portal
templates/results, wardrive logs, SSID lists, and the firmware's own configuration — plus the
contents of an SD card inserted in that device.

**Owner:** an individual conducting *authorized* security testing who wants their own field device
to be confidentiality-protected if it is lost, stolen, or taken from them. This is a **defensive,
owner-only, single-device** control. It is the embedded-hardware analogue of full-disk encryption
with a duress/nuke password (Kali LUKS Nuke), a duress PIN (GrapheneOS), or a dead-man cable
(BusKill / USBKill).

**Explicit non-goal / prohibited use:** destroying data to obstruct a lawful investigation or to
defeat a valid legal order. That is illegal in most jurisdictions (e.g. US 18 U.S.C. §1519
obstruction; analogous statutes elsewhere) and is **not** a supported use case. Use this only on
your own device, for confidentiality, within the law that applies to you.

## Adversaries considered

| # | Adversary | Capability | What we do about it |
|---|-----------|-----------|---------------------|
| A1 | Casual finder / thief | Powers it on, pokes the UI | Boot password gate; wrong attempts → lock/backoff (disarmed) or wipe (armed). |
| A2 | Opportunist with a laptop | Tries to read/flash over USB | T2: Flash Encryption makes a dump meaningless; Secure Boot + disabled UART download stop reflash-past-gate. T1: **not** protected — documented. |
| A3 | Tamper / snatch | Opens the case or yanks the device | Dead-man arming line (armed): case-open/cut/**disconnect** reads NOT-ARMED → wipe. Best-effort given power-loss timing. **Limit:** the single-ended line detects open/cut/disconnect, **not** an attacker who *clamps* the pin to the armed level (see "stuck-at" note below). |
| A4 | Coercion ("unlock it") | Demands the password | Duress: entering a wrong password the configured number of times wipes instead of unlocking. (Owner's choice; understand local law on compelled passwords.) |
| A5 | Forensics lab | Chip-off, JTAG, FTL spare-area recovery | T2 (encryption) is the only real defense. SD remanence and a *removed* SD card are out of scope. Honestly documented as a limit. |

## Trust boundaries

- **Provisioning host** (the flasher running `provision.py`) is trusted at flash time. The password
  is typed there, hashed with PBKDF2-HMAC-SHA256 + a random salt, and only `{salt, hash, params}`
  ever reach the device. The host zeroizes the plaintext; it is never logged or passed as an argv.
- **NVS `guardcfg`** is trusted storage *on* the device. The salted hash is safe in plaintext NVS.
  Hiding `arm_pin`/`arm_level` from a chip-reader requires NVS encryption (T2).
- **The Marauder app** is *not* part of the gate's TCB in the GUARDIAN variant (it runs only after
  the gate passes). In the FORK variant the gate shares the image with Marauder; the gate code runs
  first in `setup()` and must complete before any Marauder subsystem starts.

## Failure-mode posture (fail safe = do not destroy)

The design deliberately biases away from accidental destruction:

- **Unprovisioned ⇒ cannot wipe.** **Master-disarmed (default) ⇒ cannot wipe.** Both are required
  before any trigger is even evaluated.
- **Correct password always wins** and never wipes, regardless of the arming line (except the
  dead-man pre-check, which is a hard hardware gate the owner explicitly enabled).
- **Undervoltage boot ⇒ treated as DISARMED** so a brownout cannot spuriously trip the line.
- The one fail-*toward*-destruction behavior — a cut arming wire wiping an **armed** board — is the
  dead-man feature itself, is opt-out (`deadman=0`), and is loudly documented.

## Residual risks (accepted / documented, not solved)

- T1 builds are bypassable by a capable attacker (reflash/chip-pull). Use T2 for real assurance.
- SD overwrite cannot guarantee destruction of FTL-remapped cells; encryption-at-rest is the fix.
- A device snatched **while powered and mid-wipe** may not finish the bulk erase (no instant
  crypto-erase on ESP32).
- **Dead-man "stuck-at-armed" defeat (A3).** The arming line is **single-ended**, so it can only
  detect that the line has left the armed level — i.e. an OPEN/CUT/DISCONNECT (the wire reads
  NOT-ARMED ⇒ wipe when armed). It **cannot** detect an attacker who physically **clamps** the pin
  to the armed level (e.g. a probe/jumper holding it at `arm_level` while the case is opened): the
  read stays ARMED and the dead-man never fires. Detecting a stuck-at fault would require a
  **differential or actively-toggling** arming signal (the firmware verifying an expected
  edge/pattern rather than a static level), which this single-pin design does not implement.
  Accepted limit, not solved.
- Compelled-password law varies by jurisdiction; the duress feature is a personal-risk decision.
- The boot-chain self-erase ("brick") is unverified until the hardware spike passes.
