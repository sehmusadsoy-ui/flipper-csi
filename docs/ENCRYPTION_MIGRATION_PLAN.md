# Encryption migration plan — ESP32-S2 Wi-Fi credentials

**Status: PLAN ONLY.** No firmware was flashed, no eFuse was burned, no NVS was
erased or modified. Every hardware step below needs the owner's explicit,
separate approval. Background and threat model:
[WIFI_CREDENTIAL_STORAGE_SECURITY.md](WIFI_CREDENTIAL_STORAGE_SECURITY.md).

## Current state (verified from source, 2026-11-21)

| Item | Value | Source |
| --- | --- | --- |
| Wi-Fi SSID/password | plaintext `Credentials` blob, NVS namespace `csi_radar`, key `wifi` | `esp32/main/main.c` (`nvs_set_blob`) |
| Wi-Fi driver storage | `WIFI_STORAGE_RAM` (driver does not persist) | `esp32/main/main.c` |
| Flash encryption | not set | `esp32/sdkconfig.verified` |
| NVS encryption | not set | `esp32/sdkconfig.verified` |
| Secure Boot | not set (SoC supports Secure Boot V2 RSA) | `esp32/sdkconfig.verified` |
| Flipper side | SSID/password only sent over UART as hex, never written to SD logs | `flipper_app/csi_radar.c`, `PROTOCOL.md` |

Risk: someone with physical access to the board or a flash dump may read the
Wi-Fi passphrase. No remote path is known.

## Options

| Option | Protects | Hardware risk | Reversible | Notes |
| --- | --- | --- | --- | --- |
| **A. Do not persist the password on the ESP** | flash dumps of the ESP | none | yes | Flipper re-sends credentials after each ESP boot; moves plaintext to the Flipper SD instead (see below). Software-only. |
| **B. Flash Encryption (Development mode) + NVS encryption** | flash dumps | medium: burns eFuses, limited reflash count | partially (dev mode allows a few plaintext reflashes) | Needs an `nvs_keys` partition → **partition table change**, existing NVS cannot be kept. |
| **C. Flash Encryption (Release mode) + Secure Boot V2** | flash dumps and unsigned firmware | high: one-way eFuses, bricking possible on mistakes | **no** | Production only, after B is proven on a spare board. |

Recommendation: **A as interim**, then **B on a spare board** as a lab exercise.
**C only after B passes all gates, on one board, with a written key-custody plan.**

### Option A detail (software only)
- ESP keeps credentials in RAM only; on `HELLO` the Flipper sends `WIFI ...` from its
  own settings. Flipper storage would then hold the password: store it in a
  separate file, never in CSV logs, never in screenshots, and document that the
  Flipper SD is not encrypted. Consider "do not remember password" as the default.
- Migration: first boot of the new ESP firmware deletes the legacy `wifi` blob
  **only after** a successful connection with Flipper-provided credentials.
- Tests: host protocol tests, malformed/oversized `WIFI` frames, power loss
  between connect and blob deletion, reconnect after ESP reset.

### Option B detail (one spare board, lab only)
1. Record board revision, eFuse summary (`espefuse.py summary`, read-only) and the
   current partition table. Store the record without any secrets.
2. Back up the full flash image to an encrypted local location; verify it restores
   on the same board **before** any eFuse operation.
3. Add `nvs_keys` partition; enable `CONFIG_FLASH_ENCRYPTION_ENABLED`
   (Development mode) and `CONFIG_NVS_ENCRYPTION`. Build is reproducible and its
   sdkconfig is committed **without keys**.
4. **Approval gate 1:** owner approves the exact command list and board serial.
5. First boot burns the flash-encryption key eFuse and encrypts flash. Re-provision
   Wi-Fi from the Flipper (old NVS is not migrated because the layout changed).
6. Verify: app works, `nvs_get_blob` round-trip, raw flash read shows no plaintext
   SSID/password (check locally, do not publish dumps).
7. Document remaining development-mode reflash budget (`FLASH_CRYPT_CNT`).

### Option C gate (not scheduled)
Release-mode flash encryption and Secure Boot V2 permanently disable plaintext
flashing and require signed images. Prerequisites: Option B PASS, offline signing
key custody (never in Git or CI), documented recovery, and a separate approval.

## Acceptance checklist (all PENDING)

| Check | Status |
| --- | --- |
| Option A implemented with host tests | PENDING |
| Legacy blob removal after verified connection | PENDING |
| Spare board identified and eFuse summary recorded | PENDING |
| Full flash backup restored successfully before eFuse change | PENDING |
| Option B build reproducible, no keys in repo | PENDING |
| Raw flash inspection shows no plaintext credentials | PENDING |
| Owner approval for any eFuse / flash / NVS operation | REQUIRED, not given |

## Hard rules
- No eFuse burning, flash erase, NVS reset or firmware flashing without explicit
  owner approval for that specific board and command list.
- No keys, passwords, flash dumps or eFuse key material in Git, CI, logs, issues
  or releases.
- No PASS without a real, observed device result.
