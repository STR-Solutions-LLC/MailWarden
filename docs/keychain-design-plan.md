# MailWarden Keychain Migration — Implementation-Ready Design

**Status:** Design only. Approved for implementation AFTER live M1 testing of the current
beta is complete. Nothing in this document has been built.
**Repo baseline:** main @ `dd70696`.
**Audience:** an engineer with zero MailWarden context. Every claim about current code is
cited `file:line` against the baseline above.

---

## 0. Why this exists, and the two named risks

MailWarden stores three kinds of secrets in plaintext JSON today. Moving them into the
macOS login Keychain is REQUIRED before public distribution (owner decision, 2026-07-05)
but was deliberately kept out of the 1.7.x beta because of two risks this design must
resolve explicitly:

1. **Headless prompts.** Two of the three secret-reading processes run under launchd with
   no UI. If Keychain access ever triggers a permission dialog for them, the dialog
   appears (or silently queues) where the owner never sees it, and filtering dies.
2. **Re-sign survival.** Every app update replaces the signed binaries. If Keychain ACLs
   are bound to the *specific* binaries that created the items, the first update after
   migration locks the app out of its own secrets.

Both are resolved in §4 (trust anchored on the Developer ID **team identifier** via
code-signing designated requirements, not on binary hashes) and §6 (migration never
deletes plaintext until a real headless read has succeeded).

---

## 1. Ground truth — where secrets live and who touches them today

### 1.1 The secrets and their storage

All secrets live in one file: `~/MailWarden/config/config.json`.

| Secret | Config location | Defined at |
|---|---|---|
| Anthropic API key | `anthropic.api_key` | `app/mailwarden_app/config_io.py:64` |
| IMAP password, one per account | `accounts[i].password` (flat per-account schema) | `config_io.py:99` (smtp default block uses the same key name; per-account shape built at `config_io.py:128-150`, field at `:146`) |
| SMTP password (single global) | `smtp.password` | `config_io.py:95-102`, built at `config_io.py:153-169` |

File permissions: `config_io.save_config()` chmods to `0600` after every atomic write
(`config_io.py:218-224`, comment at `:220`: "readable only by the user (contains API key +
email passwords)"). The engine's own writer `save_config_atomic()`
(`payload/MailWarden/src/spam_filter.py:1730-1741`) writes via `tempfile.mkstemp`, which
also produces `0600`. So the file is consistently `0600` — but plaintext.

**Plaintext copies also exist in upgrade backups.** On every version upgrade,
`bootstrap._backup_existing()` copies `config/` (including `config.json`) to a timestamped
snapshot under `~/MailWarden-upgrade-backup/<stamp>/config/`
(`app/mailwarden_app/bootstrap.py:150-165`). Multiple snapshots accumulate — one per
upgrade. Any migration must scrub these too (§6.4).

`~/MailWarden` is directly under the home directory (`app/mailwarden_app/paths.py:10-11`),
so it is not iCloud-synced (Desktop & Documents sync doesn't cover it), but it IS in Time
Machine backups. Keychain items are excluded from both concerns by construction.

### 1.2 The three processes and every secret reader

**Process architecture.** launchd (via SMAppService-registered LaunchAgents bundled at
`Contents/Library/LaunchAgents/`, copied there by `build_installer.sh:250-261`) runs the
bundled Python interpreter directly:

- `com.mailwarden.filter` → `/Applications/MailWarden.app/Contents/MacOS/python
  …/Contents/Resources/launcher.py --run-filter`, every 5 minutes
  (`app/resources/Library/LaunchAgents/com.mailwarden.filter.plist`, ProgramArguments block).
- `com.mailwarden.report` → same binary, `--run-report`, daily at 08:00
  (`com.mailwarden.report.plist`).
- `com.mailwarden.menubar` → same binary, `--menu-bar` (reads NO secrets — it loads config
  only for account names/status, `app/mailwarden_app/menu_bar.py:154-157`).

`launcher.py` imports `mailwarden_app.app_entrypoint` (`app/launcher.py:67`), whose
`_run_user_script()` (`app/mailwarden_app/app_entrypoint.py:223-297`) executes the engine
scripts **from the user-writable copy at `~/MailWarden/src/`** via `runpy.run_path`
(`app_entrypoint.py:236, 292-296`). Those copies are installed/refreshed from the bundle's
`payload/MailWarden/src/` by `bootstrap.bootstrap_runtime()`
(`app/mailwarden_app/bootstrap.py:238-333`).

The GUI process is different: the Dashboard / Setup Assistant runs as
`Contents/MacOS/MailWarden` (the py2app stub built from `app/setup_app.py`, `APP =
["launcher.py"]` at `setup_app.py:99`). **So there are exactly two main-executable code
identities that must read secrets:**

- `Contents/MacOS/MailWarden` — identifier `com.strsolutions.mailwarden` (verified with
  `codesign -dv` on the built app; matches `CFBundleIdentifier`, `setup_app.py:109`).
- `Contents/MacOS/python` — identifier `python` on the final signed bundle (see the
  batch-4 correction note in §4.2; the interpreter is python.org's, copied in by py2app,
  but the Developer-ID re-sign derives the identifier from the basename).

**Engine readers (run as `Contents/MacOS/python` under launchd):**

- `spam_filter.py` — `load_config()` reads the JSON raw (`payload/MailWarden/src/spam_filter.py:45,
  149-151`); IMAP login `conn.login(account["username"], account["password"])`
  (`spam_filter.py:6314`, in `connect_imap`); Anthropic client from
  `api_config.get("api_key")` (`spam_filter.py:7298`; also passed into
  `classify_eml_offline` at `:6048, 6229-6237`); SMTP password for reply-corridor /
  notification mail (`spam_filter.py:2227`).
- `daily_report.py` — own `load_config()` (`daily_report.py:29, 91-92`); API key at
  `daily_report.py:1588` (used at `:1659, 1741`); SMTP password at `:1508`.
- `learn_signals.py` — own `load_config()` (`learn_signals.py:49, 91-92`); Anthropic
  client at `:1173`. (The learner is spawned by the filter, not by its own agent — the
  legacy learner agent is cleaned up by `scripts/postinstall:33-37`. Same process identity.)
- `utils.py` (shared by all three) — IMAP login at `utils.py:72` (`connect_imap` twin) and
  SMTP login at `utils.py:183, 202`.

**Engine writer of config.json (critical for §5.3):** the ONLY engine write is the EULA
sent-tracking merge: `deliver_eula_if_needed` re-reads config fresh under lock and calls
`save_config_atomic(fresh, CONFIG_PATH)` (`spam_filter.py:1917-1922`). If loading hydrates
secrets into the dict, this save would leak them back to disk — the design handles this
with strip-on-save (§5.3). `learn_signals.py` explicitly never writes config
(`learn_signals.py:118`).

**GUI readers/writers (run as `Contents/MacOS/MailWarden`):**

- **Setup Assistant** (`app/mailwarden_app/setup_assistant.py`) — collects the API key
  (masked entry, `setup_assistant.py:254-255`), validates it live
  (`:279-291` → `validators.validate_api_key`, `app/mailwarden_app/validators.py:39`),
  collects IMAP/SMTP passwords (`:686, 709, 758, 847-850`), and writes them into config via
  `new_account_entry` / `smtp_config_from_account` (`:1050, 1061`; `cfg["anthropic"]["api_key"]`
  at `:75`).
- **Dashboard Settings tab** — API key masked entry (`app/mailwarden_app/dashboard.py:3873-3884`),
  loaded back into the field on refresh (`dashboard.py:4002`), saved by `_on_save_api`
  (`:4038-4058`, sets `anthro["api_key"]` at `:4050`), validated by `_on_validate_api`
  (`:4097-4103`).
- **Dashboard Accounts tab** — add/edit/remove accounts through
  `setup_assistant.AccountFormDialog`, persisting the whole account dict including
  `password` (`dashboard.py:1440-1493`).
- **Dashboard background IMAP jobs** — junk-folder probe (`dashboard.py:658`), Train-folder
  check (`:768` in `_check_train_folders_bg`), Train-folder creation (`:855` in
  `_create_train_folders_bg`), plus the Check-an-Email / Teach flows which pass
  `api_key` from config (`:2138-2139, 2616-2617, 3587-3588`).
- **Dashboard uninstall** — optionally deletes `~/MailWarden` because "config holds the API
  key + email passwords" (`dashboard.py:4618-4619`; user-facing copy at `:4412, 4427, 4553`).
- **CLI/dev paths** — `--classify-eml` reads `$ANTHROPIC_API_KEY` env, else
  `anthropic.api_key` from config (`app_entrypoint.py:391-400`); `--status` prints
  non-secret config fields only (`app_entrypoint.py:43-61`).

### 1.3 Install, build, signing, and update mechanics

- **Installer:** `pkgbuild` stages `/Applications/MailWarden.app` with
  `scripts/` as pkg scripts (`build_installer.sh:373-379`); `scripts/postinstall` runs as
  root, resolves the console user, and `open`s the app as that user
  (`scripts/postinstall:14-43`). It never touches `~/MailWarden` itself — first-launch
  `bootstrap_runtime()` does (Dashboard-only; headless agents skip bootstrap,
  `app_entrypoint.py:540-552`).
- **Build runtime:** python.org **universal2 CPython 3.12** is mandatory
  (`build_installer.sh:103-131`); the shipped app is arm64-only
  (`setup_app.py:126`, `OPTIONS["arch"] = "arm64"`).
- **Signing:** every nested Mach-O is signed inside-out with
  `Developer ID Application: STR Solutions, LLC (6BXSAHWH29)`, hardened runtime +
  timestamp (`build_installer.sh:286-349`); the outer app is signed with
  `app/MailWarden.entitlements` (network client + user-selected files only — no keychain
  entitlements exist today). The .pkg is productsigned with the team's
  Developer ID Installer cert and notarized (`codesign/sign_and_notarize.sh:66-80`).
- **Updates:** a new .pkg simply over-installs `/Applications/MailWarden.app`
  (new binaries, same paths), then bootstrap refreshes `~/MailWarden/src/` from the new
  bundle, with version-tag and content-drift checks (`bootstrap.py:115-147, 290-333`).
  SMAppService registrations are force-refreshed once per version
  (`app_entrypoint.py:554-612`).

### 1.4 Honest scoping note (threat model)

The launchd agents execute user-writable code (`~/MailWarden/src/*.py`) inside the trusted
`Contents/MacOS/python` binary (`app_entrypoint.py:223-297`). Keychain ACLs authenticate
the *main executable*, not the script it runs — so any local process running as the same
user could invoke that python with its own script and read the items. That is the **same**
threat model as today's `0600` config.json (any same-user process can read it). What the
Keychain migration genuinely buys: secrets are encrypted at rest, absent from Time Machine
backups of `~/MailWarden`, absent from the upgrade-backup snapshots, absent from any
future "export settings / diagnostics" feature, invisible to casual `cat`/grep/file-sharing
accidents, and locked when the keychain is locked. It does NOT create process-level
isolation on the same user account. Do not oversell it in copy.

---

## 2. Design overview

- One new tiny module, duplicated per the two-trees convention (the GUI package and the
  engine never import each other — see the duplication precedent documented at
  `config_io.py:1074-1090`): `app/mailwarden_app/keychain_store.py` and
  `payload/MailWarden/src/keychain_store.py`. Byte-identical where logic overlaps, with a
  drift-guard test like `tests/test_fp_dashboard_approve.py` does for the FP helpers.
- Secrets become **generic-password items in the login keychain**, one item per secret,
  ACL'd to *both* executables at creation time via Security.framework (PyObjC), with trust
  recorded as each executable's **designated requirement** — which for Developer ID code
  is identifier + Apple anchor + **team ID**, so re-signed updates keep access (§4).
- `config.json` keeps its exact schema shape; secret fields hold the sentinel string
  `"@keychain:v1"` after migration. Loaders hydrate real values in memory; savers strip
  (§5). The 10k-line engine internals (`account["password"]` passed everywhere) are
  untouched.
- A `secrets.backend` config flag (`"config"` | `"keychain"`) is the master switch and the
  beta kill-switch (§7).
- Migration is a resumable state machine that verifies a **real headless read from the
  actual launchd-spawned filter process** before any plaintext is deleted (§6).
- Filtering **fails closed** on any keychain read failure: the tick is skipped entirely,
  nothing is classified or moved, and the failure is surfaced via a status file the
  Dashboard and menu bar read (§7.1).

---

## 3. Storage schema

**Item class:** `kSecClassGenericPassword`, in the **login keychain** (the default
keychain of the user session; no `kSecUseKeychain` override in production code).

Why the login keychain and not alternatives:

- *System keychain* — wrong scope (machine-wide, needs admin to write, secrets are
  per-user) and wrong unlock model.
- *A custom MailWarden keychain file* — would need its own password or a
  stored-in-plaintext unlock secret, recreating the original problem, and adds first-unlock
  prompts.
- *Data-protection keychain* (`kSecUseDataProtectionKeychain`) with a keychain access
  group — this is the modern prompt-free sharing mechanism, but access groups require the
  `keychain-access-groups` / application-identifier entitlements, which for Developer ID
  distribution means embedding provisioning profiles — including one for the bare nested
  `python` binary, which is not a bundle and cannot carry a profile in any supported way.
  Not viable for this app's two-executable layout.
- *Login keychain with ACLs* — legacy ("file-based") keychain APIs, deprecated but fully
  functional through macOS 15/26, and the only mechanism that lets two differently-named
  executables in one bundle share an item **with zero prompts** under Developer ID
  signing. This is the pragmatic, correct choice. Revisit only if Apple actually removes
  the SecAccess APIs.

The login keychain is unlocked automatically at GUI login by loginwindow (when the
keychain password matches the login password — the default), and MailWarden's agents are
**GUI-session LaunchAgents** registered via SMAppService, which only run inside a GUI
login session. So in the normal case the keychain is always unlocked when the agents run.
The abnormal cases are handled in §7.1.

**Item naming.** One item per secret (not a consolidated JSON blob — per-item
add/change/delete maps 1:1 onto the existing UI actions: rotate API key, edit one
account's password, remove an account; and a partial failure affects one credential, not
all of them):

| Secret | `kSecAttrService` | `kSecAttrAccount` | `kSecAttrLabel` (Keychain Access display) |
|---|---|---|---|
| Anthropic API key | `com.strsolutions.mailwarden` | `anthropic-api-key` | `MailWarden — Anthropic API key` |
| IMAP password | `com.strsolutions.mailwarden` | `imap|<imap_host>|<username>` (both lowercased, from `accounts[i].imap_host` / `.username`, `config_io.py:143-145`) | `MailWarden IMAP — <username>` |
| SMTP password | `com.strsolutions.mailwarden` | `smtp|<host>|<username>` (from the `smtp` block, `config_io.py:95-102`) | `MailWarden SMTP — <username>` |

`kSecValueData` = the secret, UTF-8 encoded. No `kSecAttrSynchronizable` (never iCloud-sync
these). The account key is derived deterministically from config fields, so the sentinel
needs no payload and there is no reference bookkeeping to corrupt.

Derivation edge cases the helper must handle:

- Editing an account's host or username changes the derived key → the account-edit flow
  deletes the item under the OLD key and creates one under the NEW key (§8.2).
- Two accounts with identical `(imap_host, username)` share one item (they are the same
  mailbox); on account removal, delete the item only if no *other* account derives the
  same key.

---

## 4. Access from headless launchd — ACLs, designated requirements, and re-sign survival

This is the crux. Read this section before writing any code.

### 4.1 How file-keychain access control actually decides

For an item in the login keychain, securityd grants a read to a process without any UI
when BOTH pass:

1. **ACL check** — the item's ACL contains a "trusted application" entry whose recorded
   *code requirement* the requesting process's main executable satisfies. When a trusted
   application is created from a signed binary, the requirement recorded is that binary's
   **designated requirement (DR)** — not a file hash — so any future binary satisfying
   the same DR stays trusted.
2. **Partition-list check** (macOS 10.12+) — the item's partition list must include the
   requesting code's signing partition. Items created programmatically by an app signed
   with team `6BXSAHWH29` are automatically stamped `teamid:6BXSAHWH29`; any binary signed
   by that team passes. Items created by Apple's `security` CLI instead get
   `apple-tool:,apple:` — which our binaries are NOT in (this is why the CLI is rejected
   in §5.1).

Any failure of either check triggers the "MailWarden wants to use your confidential
information" dialog — which in a launchd context is exactly risk #1. So the design must
guarantee both checks pass for both executables from item creation onward.

### 4.2 The designated requirements we get, and the strategy

Current identifiers (verified on the built bundle with `codesign -dv`):

- `Contents/MacOS/MailWarden` → identifier `com.strsolutions.mailwarden`
- `Contents/MacOS/python` → identifier `python`

> **Batch-4 ground-truth correction (2026-07-08).** An earlier draft of this
> document stated the bundled interpreter's identifier is `org.python.python`.
> That was taken from python.org's framework binary / the pre-signing py2app
> copy. The value that actually ships is the bare `python`: the nested-signing
> loop runs `codesign --force --sign <DevID>` with no `-i`, so codesign derives
> the identifier from the file's basename (`python`). Every past notarized beta
> shipped it this way and Apple accepted them. The frozen expectation and the
> build gate use `python`; keychain trust is unaffected because ACLs are anchored
> by binary *path* (`SecTrustedApplicationCreateFromPath`), which records the
> real DR whatever the identifier string is. Occurrences of `org.python.python`
> elsewhere in this document should be read as `python`.

When `build_installer.sh` signs these with the Developer ID Application cert
(`build_installer.sh:286-349`) and no explicit `-r` requirement, codesign generates the
**default Developer ID DR**, which has the form:

```
identifier "<identifier>" and anchor apple generic
  and certificate 1[field.1.2.840.113635.100.6.2.6]        /* Developer ID CA */
  and certificate leaf[field.1.2.840.113635.100.6.1.13]    /* Developer ID leaf */
  and certificate leaf[subject.OU] = "6BXSAHWH29"          /* the TEAM, not the cert */
```

(Verify after any build with `codesign -d -r- <binary>`. Note: the ad-hoc intermediate in
`app/dist/` shows `designated => cdhash H"…"` — that is what ad-hoc code gets, and it is
why dev builds can never hold stable keychain access; the DR above only exists on the
Developer-ID-signed staged copy that actually ships.)

**Strategy:**

- Trusted-application entries are created from the two *installed, Developer-ID-signed*
  executables at their canonical paths (`/Applications/MailWarden.app` and
  `/Applications/MailWarden.app/Contents/MacOS/python`). The recorded requirement is each
  one's default DR shown above.
- **Update survival (risk #2 resolved):** an update over-installs new binaries at the same
  paths, re-signed with (a) the same cert, (b) a *renewed* cert, or (c) a *different*
  Developer ID Application cert of the same team — in all three cases the leaf OU is still
  `6BXSAHWH29` and the identifiers are unchanged, so the stored DRs still match and access
  continues with no prompt and no re-ACL step. Nothing binds to a certificate serial,
  expiry, or cdhash.
- **Identifier stability is now a shipping invariant.** `com.strsolutions.mailwarden` and
  `python` (see the correction note above — NOT `org.python.python`) must never change once
  the first keychain release ships, or stored DRs stop matching. This build-gate assertion
  is implemented in `scripts/check_designated_requirements.py`, invoked by
  `build_installer.sh` in the Developer ID branch after signing: `codesign -d -r- …/MacOS/python`
  must pin `identifier python` (codesign renders this bare identifier unquoted) and
  `subject.OU] = "6BXSAHWH29"`, same for the outer app (`identifier "com.strsolutions.mailwarden"`,
  quoted) — die otherwise. (Decision: do NOT rename the python identifier to something
  MailWarden-specific. Tighter scoping is marginal — only STR-signed binaries can match
  anyway because of the team clause — and keeping the identifier that every past beta
  already has removes a whole class of "which identifier did the item trust?" states.)
- **Team-ID rotation** (changing Apple developer account / legal entity) is the one event
  this cannot survive: stored DRs would stop matching and every read would prompt. If that
  is ever planned, ship a release FIRST that (while still trusted) re-creates all items
  with ACLs trusting the new team's DRs, then rotate. Recorded here so the failure mode is
  a documented procedure, not a surprise. (See Open Questions.)

### 4.3 No-UI discipline in headless processes

Both engine processes must disable Security UI for their lifetime so nothing can ever
block a tick invisibly:

- Call `SecKeychainSetUserInteractionAllowed(False)` once at engine startup (in the
  keychain_store module init when running with `--run-filter` / `--run-report` /
  `--run-learner`). A locked keychain or ACL miss then returns
  `errSecInteractionNotAllowed` (-25308) / `errSecAuthFailed` (-25293) instead of showing
  a dialog, and the tick fails closed (§7.1).
- The GUI process leaves interaction allowed — if macOS ever needs to ask, the owner is
  present to answer, and "Always Allow" repairs ACL drift on the spot.

### 4.4 Login-keychain unlock timing vs agent start

Sequence on a normal boot: FileVault/loginwindow authenticates the user → loginwindow
unlocks the login keychain with the login password → launchd starts the user's GUI-domain
LaunchAgents (`RunAtLoad` fires now; the filter plist has `RunAtLoad=true` +
`StartInterval=300`). Before first login there is **no GUI session and the agents do not
run at all**, so "reboot, nobody logged in yet" is a non-case for prompts — the filter
simply isn't running (same as today).

Two real abnormal cases:

1. **Race at login:** `RunAtLoad` can occasionally fire before the keychain unlock
   completes. The read returns `errSecInteractionNotAllowed`; the tick is skipped; the
   next 5-minute wake succeeds. Self-healing, no owner action, log one WARNING.
2. **Keychain password ≠ login password** (e.g., password was reset via Recovery or
   directory tools): the login keychain stays locked for the whole session, every tick
   fails closed, and the owner must be told. §7.1 defines the surfacing (menu bar warning
   + Dashboard banner naming the fix: Keychain Access → change login-keychain password to
   match).

---

## 5. API choice and the exact call surface

### 5.1 `security` CLI — rejected

`security add-generic-password -T <app>` looks tempting but fails the crux requirement:
items created by `/usr/bin/security` are stamped with the `apple-tool:,apple:` partition
list, so our (non-Apple) binaries fail the partition check and prompt on first read. The
only repair is `security set-generic-password-partition-list -S teamid:6BXSAHWH29 …`,
which **requires the keychain password on the command line or interactively** — not
available headlessly and not something we will ask the owner to type into Terminal.
Reading via the CLI from the engine has the mirror problem (the ACL would have to trust
`/usr/bin/security`, whereupon *any* process could read the item via the CLI without a
prompt… after the user's first "Always Allow"). Verdict: the CLI is for the owner's manual
inspection only; production code never shells out to it.

### 5.2 Security.framework via PyObjC — chosen

The bundled runtime is python.org CPython 3.12 (`build_installer.sh:103-110`) and the
bundle already ships PyObjC core + framework wrappers, with an established precedent for
adding one: `pyobjc-framework-ServiceManagement` was added exactly this way for
SMAppService (`build_installer.sh:143-153`, `setup_app.py:175` — the "ServiceManagement"
packages entry). Add **`pyobjc-framework-Security`** identically (§9). PyObjC gives real
CoreFoundation bridging (dict ↔ CFDictionary, bytes ↔ CFData, proper CF memory
management) that a hand-rolled ctypes layer would have to reimplement and get subtly
wrong; ctypes is rejected on maintenance grounds.

Exact call surface (`keychain_store.py`, both copies):

```python
from Security import (
    SecItemAdd, SecItemCopyMatching, SecItemDelete,
    SecAccessCreate, SecTrustedApplicationCreateFromPath,
    SecKeychainSetUserInteractionAllowed,
    kSecClass, kSecClassGenericPassword,
    kSecAttrService, kSecAttrAccount, kSecAttrLabel,
    kSecValueData, kSecAttrAccess,
    kSecReturnData, kSecMatchLimit, kSecMatchLimitOne,
)

SERVICE = "com.strsolutions.mailwarden"
APP_PATH = "/Applications/MailWarden.app"
PY_PATH = "/Applications/MailWarden.app/Contents/MacOS/python"

errSecSuccess = 0
errSecItemNotFound = -25300
errSecDuplicateItem = -25299
errSecAuthFailed = -25293
errSecInteractionNotAllowed = -25308


def _access():
    # Trust BOTH executables. PyObjC convention: pass None for out-params,
    # receive (OSStatus, value) tuples.
    status, gui = SecTrustedApplicationCreateFromPath(APP_PATH, None)
    if status != errSecSuccess:
        raise KeychainError("trusted-app (app)", status)
    status, py = SecTrustedApplicationCreateFromPath(PY_PATH, None)
    if status != errSecSuccess:
        raise KeychainError("trusted-app (python)", status)
    status, access = SecAccessCreate("MailWarden", [gui, py], None)
    if status != errSecSuccess:
        raise KeychainError("SecAccessCreate", status)
    return access


def write_secret(account_key: str, label: str, value: str) -> None:
    """Create-or-replace. Delete+add (never SecItemUpdate) so the ACL is
    always rebuilt from the CURRENT installed binaries."""
    delete_secret(account_key, missing_ok=True)
    attrs = {
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: SERVICE,
        kSecAttrAccount: account_key,
        kSecAttrLabel: label,
        kSecValueData: value.encode("utf-8"),
        kSecAttrAccess: _access(),
    }
    status, _ = SecItemAdd(attrs, None)
    if status != errSecSuccess:
        raise KeychainError("SecItemAdd", status)


def read_secret(account_key: str) -> str | None:
    """None = item absent. Raises KeychainLocked on -25308/-25293 so callers
    can distinguish 'not migrated' from 'locked/denied' (fail-closed path)."""
    query = {
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: SERVICE,
        kSecAttrAccount: account_key,
        kSecReturnData: True,
        kSecMatchLimit: kSecMatchLimitOne,
    }
    status, data = SecItemCopyMatching(query, None)
    if status == errSecItemNotFound:
        return None
    if status in (errSecInteractionNotAllowed, errSecAuthFailed):
        raise KeychainLocked(status)
    if status != errSecSuccess:
        raise KeychainError("SecItemCopyMatching", status)
    return bytes(data).decode("utf-8")


def delete_secret(account_key: str, missing_ok: bool = False) -> None:
    query = {kSecClass: kSecClassGenericPassword,
             kSecAttrService: SERVICE, kSecAttrAccount: account_key}
    status = SecItemDelete(query)
    if status == errSecItemNotFound and missing_ok:
        return
    if status not in (errSecSuccess, errSecItemNotFound):
        raise KeychainError("SecItemDelete", status)
```

Notes for the implementer:

- `SecAccessCreate` / `SecTrustedApplicationCreateFromPath` are deprecated (10.15) but
  present and functional; suppress the deprecation noise, do not "modernize" to
  `kSecUseDataProtectionKeychain` (see §3 for why that cannot work here).
- **Change = delete + add**, never `SecItemUpdate`: update cannot replace `kSecAttrAccess`,
  and rebuilding the ACL from the binaries currently on disk at every write is the
  self-healing property that keeps items adoptable across odd states.
- Writes happen **only in the GUI process** (wizard, Settings, Accounts, migration,
  revert). The engine only reads. This keeps ACL creation in the one process where a
  surprise dialog would at least be visible.
- The engine twin imports `Security` successfully because `_run_user_script` runs inside
  the bundled interpreter with the bundle's site-packages on `sys.path`
  (`launcher.py:27-30`). When the import fails (running the engine from a source checkout,
  tests, CI), the module exposes `available() -> False` and the config backend is used —
  dev environments keep working with plaintext config exactly as today.
- For tests only, the helper accepts an injected keychain ref (`kSecUseKeychain` on add,
  `kSecMatchSearchList` on read) so integration tests can run against a throwaway
  `security create-keychain` keychain (§10.1). Production code never passes it.

### 5.3 Config integration: sentinel, hydrate-on-load, strip-on-save

`config.json` schema is unchanged in shape. After migration, every secret field holds the
sentinel `"@keychain:v1"`. New top-level block (back-filled by the existing `_deep_merge`
machinery, `config_io.py:172-215`):

```json
"secrets": {
  "backend": "config",          // "config" (today) | "keychain"
  "migration": {"state": "none", "verified_tick_at": "", "scrubbed_at": ""}
}
```

**Hydration (read side).** Add `keychain_store.hydrate(config) -> dict` and call it at the
end of every loader — `config_io.load_config()` (`config_io.py:187-215`) and the three
engine `load_config()`s (`spam_filter.py:149`, `daily_report.py:91`,
`learn_signals.py:91`; all three funnel every secret use, §1.2). Behavior: if
`secrets.backend != "keychain"`, return unchanged. Otherwise for each secret field whose
value starts with `@keychain:`, derive the account key (§3) and replace the value with
`read_secret(...)`. Track failures in the returned dict under a non-persisted key
`config["_secret_errors"] = [...]` (prefix `_`, stripped on save) so callers can enforce
fail-closed. `KeychainLocked` is recorded, not raised, so loading config for non-secret
purposes (menu bar status, `--status`) still works.

**Strip (write side).** Every config writer must guarantee plaintext never lands on disk
once backend is `keychain`. There are exactly two writers (§1.1/§1.2):
`config_io.save_config()` (`config_io.py:218-224` — used by `update_config`,
`config_io.py:227-244`, which all GUI saves go through) and the engine's
`save_config_atomic()` (`spam_filter.py:1730-1741`, sole call site `:1922`). In both, when
`secrets.backend == "keychain"`, before `json.dump`: drop `_`-prefixed keys and replace
`anthropic.api_key`, `smtp.password`, and every `accounts[i].password` with the sentinel.
The strip never writes to the keychain — GUI flows that *change* a secret call
`write_secret()` explicitly first (§8), then save config (which strips). The engine never
changes secrets, so its strip is pure. This closes the EULA-merge leak (§1.2) by
construction. Add a regression test that hydrates, runs the EULA save path, and greps the
written file for the real password (must be absent).

**Peripheral readers to update:** `_run_classify_eml` reads the raw JSON for the API key
(`app_entrypoint.py:392-400`) — route it through `config_io.load_config()` (hydrated) with
the existing `$ANTHROPIC_API_KEY` env override preserved; it runs in a user Terminal
context where the keychain is normally unlocked. The Desktop eval harness
(`tools/eval_run.py`) runs on the build machine with a dev config — backend stays
`config` there; no change.

---

## 6. Migration — plaintext config → Keychain, crash-safe, verified before scrub

### 6.1 Where it runs

Migration is **Dashboard-process only** (the only process allowed to write items, §5.2,
and the only one with UI). Hook: in `_main_inner` after bootstrap and SMAppService
registration succeed (`app_entrypoint.py:544-612`), before dispatching to the Dashboard.
This is guaranteed to run right after every install/upgrade because `postinstall` opens
the app (`scripts/postinstall:42-43`), and headless agents can never enter it (they skip
this whole block, `app_entrypoint.py:540-543`). It also re-enters on every Dashboard
launch until complete, which is what makes crash states self-healing.

Preconditions to even start: `keychain_store.available()`, running from
`/Applications/MailWarden.app` (both trusted paths exist), `backend == "config"`, at least
one secret present. Dev checkouts and source runs never migrate.

### 6.2 State machine

State lives in `secrets.migration.state`, persisted via the locked `update_config`
(`config_io.py:227-244`). Every step is idempotent; re-entry at any state repeats the
current step harmlessly.

```
none → items_written → exec_verified → tick_verified → complete
                                (any step may also park at "failed:<reason>")
```

**Step 1 — `items_written`.** For each secret currently in plaintext: `write_secret()`
(delete+add upsert, §5.2). Then read each back **in-process** to confirm the write.
Plaintext remains untouched. Re-running re-upserts — safe.

**Step 2 — `exec_verified` (the executable-identity test).** The Dashboard spawns the
*other* code identity exactly as launchd does:

```
/Applications/MailWarden.app/Contents/MacOS/python \
    /Applications/MailWarden.app/Contents/Resources/launcher.py --keychain-verify
```

New dispatch flag in `app_entrypoint.main()` alongside `--diagnose`
(`app_entrypoint.py:504-509`): headless, no bootstrap, calls
`SecKeychainSetUserInteractionAllowed(False)`, reads every expected account key, prints a
JSON result `{ok, missing: [...], locked: bool}` (never values), exits 0/1. Because
keychain trust is evaluated against the main executable, this subprocess is a faithful
test of the ACL/DR path the launchd agents will use — if this passes, an agent read
cannot prompt. 10s timeout; failure parks the machine at `failed:exec_verify` and shows
the Dashboard banner (§8.4) — plaintext still intact, app fully functional on the config
backend.

**Step 3 — `tick_verified` (the real-launchd proof).** Flip `secrets.backend` to
`"keychain"` — but plaintext is STILL in the file, and hydration is amended for exactly
this window: during `migration.state != "complete"`, `hydrate()` prefers the keychain
value but falls back to a plaintext field if the read fails (**shadow mode** — zero risk
of breaking filtering mid-migration). The engine records the outcome of its keychain reads
each run into `~/MailWarden/memory/keychain_status.json`
(new `paths.KEYCHAIN_STATUS_PATH` + engine twin constant; written at the top of
`run_filter`, `spam_filter.py:7165`, and `daily_report` main, `daily_report.py:1586`):
`{ts, backend, ok, missing, locked, pid_context}` — booleans and key names only, never
values. The Dashboard then triggers a real agent run rather than waiting five minutes:
`launchctl kickstart gui/<uid>/com.mailwarden.filter` via subprocess, and polls the status
file (up to ~90s). A status record with `ok: true` written after the kickstart timestamp →
`tick_verified`. Timeout/`ok: false` → stay in shadow mode (filtering keeps working from
plaintext fallback), park at `failed:tick_verify`, banner. Re-entry retries the kickstart.

**Step 4 — `complete` + scrub.** Only now delete plaintext:

- Replace every secret field in `config.json` with the sentinel (one locked
  `update_config`; the strip-on-save makes this automatic once state flips to `complete` —
  the mutator just sets the state).
- Scrub backups (§6.4).
- Record `scrubbed_at`. Shadow fallback in `hydrate()` is now disabled by
  `state == "complete"`.

If the process crashes between any two steps, the next Dashboard launch resumes: states
are ordered, each step's work is an upsert/re-check, and plaintext exists until step 4,
whose own sub-steps (config scrub, then backups scrub) are individually idempotent
re-writes. A `failed:*` state never blocks the app — backend semantics at every state
keep filtering working (config backend through step 2; shadow mode in step 3).

### 6.3 Fresh installs (Setup Assistant)

When `keychain_store.available()` and the app runs from `/Applications` (both checked by the
`keychain_migrate.fresh_install_backend()` gate, which returns `"keychain"` only in that
case and `"config"` in dev/CI/source — DEFAULT_CONFIG stays `"config"`): the wizard's save
(`setup_assistant.py:57-75, 1036-1061`) sets the draft backend to that value, then
`provision_fresh_install` calls `write_secret()` for the API key, the IMAP password, and the
SMTP password, then writes config with sentinels and `backend: "keychain"`,
`migration.state: "complete"` — plaintext never touches disk. The
wizard's final step runs the `--keychain-verify` subprocess (step 2 above) before
declaring success; on failure it falls back to writing plaintext config
(`backend: "config"`) with a non-blocking warning — the status quo, never a bricked
first-run. Dev/source runs of the wizard skip keychain entirely.

### 6.4 Backup scrubbing

Step 4 rewrites every `~/MailWarden-upgrade-backup/*/config/config.json`
(`bootstrap.py:154` for the root, snapshot layout `:157-165`): load JSON, replace the
three secret field kinds with `"@keychain:scrubbed"`, atomic-write back (reuse
`config_io.save_json_atomic`, `config_io.py:28-39`). Unparseable/missing files are
skipped with a log line. Future upgrades back up an already-sentinel config, so backups
stay clean from then on. (Decision: scrub in place rather than delete the snapshots — the
non-secret parts of old backups retain their recovery value.)

---

## 7. Runtime failure behavior, fallback, and kill-switch

### 7.1 Tick-time failure = fail closed, loudly

In `run_filter` (`spam_filter.py:7165` onward) and `daily_report` main
(`daily_report.py:1586` onward), immediately after `load_config()`: if
`backend == "keychain"` and `config["_secret_errors"]` is non-empty (any required secret
unreadable — locked keychain, missing item, ACL denial), then: write
`keychain_status.json`, log one ERROR naming the failed keys (names, not values), and
**return without touching any mail or calling any network service**. Rationale for
skipping the whole run rather than degrading per-credential: a partial run with IMAP but
no API key would still execute deterministic junking without AI or reply-corridor
processing — a behavior no one has tested; all-or-nothing is predictable and safe.
`StartInterval=300` retries automatically; the transient login race (§4.4) self-heals on
the next wake.

Notification path (email is unavailable by definition — the SMTP secret is in the same
keychain): the **menu bar** agent (reads config/status only, `menu_bar.py:154-157`) shows
a warning state + explanatory item when `keychain_status.json` reports a failure newer
than the last success; the **Dashboard** shows a banner on launch/refresh with the
specific cause: locked keychain → "your Mac's keychain is locked; this usually means your
login password and keychain password don't match" + a button opening Keychain Access;
missing item → "Re-enter this password in Accounts/Settings" (re-saving re-creates the
item, §8); ACL denial → "Repair keychain access" button that re-runs step 1+2 of the
migration machine (delete+add rebuilds ACLs — the universal repair). All copy is draft,
subject to Matt's review per copy standards.

### 7.2 Kill-switch / revert (beta safety)

Supported, in Settings under a "Keychain (advanced)" group:

- **"Stop using the Keychain"** — Dashboard reads every item, writes real values back
  into `config.json` (0600, `config_io.py:220-224`), sets `backend: "config"`, and marks
  `migration.state: "opted_out"` — a **durable opt-out** (Batch 5, `STATE_OPTED_OUT` in
  `keychain_store.py`). BOTH revert outcomes land this same marker: a clean revert (every
  secret recovered; the items are then deleted) and a KEPT revert (some items unreadable
  and deliberately left — the clean/kept distinction survives only in the returned
  `unreadable` list, which drives the "re-enter these" warning). The opt-out is a lasting
  choice: **auto-migration NEVER re-migrates an opted-out user** (`migration_should_run`
  returns False for `opted_out`), and the marker also keeps `keychain_items_may_exist()`
  True so a later delete-data uninstall still cleans any orphaned items — including a clean
  revert whose item delete was interrupted (the §7.3 crash-window fix). Requires a readable
  keychain; if items are unreadable the button explains that re-entering credentials in
  Accounts/Settings is the recovery (that path always works — values typed in the UI are
  written wherever the current backend says).
- **"Use the Keychain"** — the re-enable control shown to an opted-out user
  (`reenable_keychain`, `keychain_group_view` packs it as the sole button in the opt-out
  state). It clears the opt-out and force-migrates the plaintext secrets back into the
  Keychain (delegates to "Re-run Keychain setup" below). A crash after the opt-out is
  cleared but before the migration completes self-heals: the state is `none` + backend
  `config`, which the auto path resumes on the next Dashboard launch.
- **"Re-run Keychain setup"** — resets state to `none` and runs the §6.2 machine again
  with `force=True`. If a concurrent cross-process revert commits between its epoch snapshot
  and the reset write, the reset aborts and reports `action: "aborted"` (opt-out preserved,
  zero keychain writes) rather than churning.
- **Headless escape hatch** for a broken GUI: `--set-secrets-backend=config` CLI flag next
  to `--set-dry-run` (`app_entrypoint.py:525-527`), performing the same revert; documented
  in Help. If the keychain itself is unreadable it writes empty strings + a WARNING that
  credentials must be re-entered.

The `secrets.backend` flag is also the global guard: every keychain code path is inert
when it reads `"config"`, which is the shipped default until the M1 gate (§10.2) passes.

### 7.3 Uninstall

The uninstall flow's "also delete settings & passwords" option
(`dashboard.py:4386, 4617-4640`) additionally deletes all `com.strsolutions.mailwarden`
service items (enumerate via `SecItemCopyMatching` with `kSecMatchLimitAll` on the
service, then delete). Keep-data uninstall keeps the items (reinstall picks them right
back up because trust is DR-based, not install-instance-based).

---

## 8. UI changes (wizard, Settings, Accounts) — entry, change, delete

All flows keep their current widgets and validation; only persistence changes, gated on
the active backend.

1. **Setup Assistant** — §6.3. No visible change except the final verify step's progress
   line.
2. **Accounts add/edit/remove** (`dashboard.py:1440-1493` + `AccountFormDialog`):
   *add* → `write_secret(imap key)` then save config with sentinel password;
   *edit* → if host/username changed, `delete_secret(old key)`; `write_secret(new key)`;
   sentinel; *remove* → `delete_secret` unless another account shares the key (§3);
   config row removed as today (`dashboard.py:1470-1483`).
3. **Settings API key** (`dashboard.py:3873-3884, 4038-4058`): Save →
   `write_secret("anthropic-api-key")`, then the existing `update_config` with sentinel
   (`:4050` becomes the sentinel write). Refresh (`:4002`) must show a masked placeholder
   (`••• stored in Keychain`) instead of loading the value into the entry; Validate keeps
   using the typed value when present, else the hydrated one.
4. **SMTP settings** (wizard-owned today, `setup_assistant.py:993-1061`): same pattern via
   the smtp key.
5. **Failure UX** — §7.1 banner/menu-bar states; **Keychain section in Settings** — §7.2
   buttons; **Help tab** (`dashboard.py:5640`) gains a short "Where are my passwords
   stored?" entry (help-copy refresh is a mandated pre-ship step — see the beta.18
   stale-help incident rule).
6. **Dashboard background IMAP jobs** (`dashboard.py:658, 768, 855`) and Check-an-Email /
   Teach (`:2138, 2616, 3587`) need **no changes** — they consume the hydrated config.

---

## 9. Build & installer changes

1. `build_installer.sh:142` — add `pyobjc-framework-Security` to the pip install, pinned
   to the resolved pyobjc-core major exactly like ServiceManagement
   (`build_installer.sh:151-153`).
2. `setup_app.py` packages list — add `"Security"` next to `"ServiceManagement"` (same
   modulegraph-drops-frameworks precedent documented there).
3. `_run_diagnose` mods list (`app_entrypoint.py:118-141`) — add `"Security"` plus a
   symbol check for `Security.SecItemCopyMatching` (mirroring the SMAppService symbol
   check at `:180-185`).
4. New build-gate assertion after Developer ID signing: DR identifier + team check on both
   executables (§4.2).
5. No entitlement changes: file-keychain ACL access requires none
   (`app/MailWarden.entitlements` stays as is). No postinstall changes: migration runs in
   the user-session app launch it already triggers (`scripts/postinstall:42`).
6. Nested-signing loop (`build_installer.sh:301-312`) is already correct for
   `Contents/MacOS/python` — no flags added or removed (deliberate, §4.2).

---

## 10. Test plan

### 10.1 Headless on the build machine (this Mac — build-only; no live mail)

- **Unit (no keychain):** account-key derivation incl. shared-mailbox edge; hydrate with
  fake store (all states: ok / missing / locked / mixed); strip-on-save for both writers —
  incl. the EULA-merge path (`spam_filter.py:1917-1922`) with hydrated config, asserting
  no plaintext in the written file; migration state machine idempotency — simulate a crash
  between every adjacent pair of states and re-enter; revert flow; sentinel round-trip
  through `_deep_merge` back-fill (`config_io.py:172-215`); drift-guard test asserting the
  two `keychain_store.py` copies' shared logic is byte-identical.
- **Integration (real keychain APIs, throwaway keychain):** `security create-keychain`
  a temp keychain, inject it via the test-only ref (§5.2), exercise
  write/read/delete/upsert semantics and error codes, delete the keychain. Runs unsigned —
  proves API mechanics, deliberately NOT the ACL/prompt behavior (ad-hoc DRs are
  cdhash-bound, §4.2 — meaningless for that).
- **Regression:** full existing suite; the offline eval gate (`tools/eval_run.py` + the
  79-email Desktop corpus) must be **byte-identical to baseline** — backend defaults to
  `"config"` and hydration is a no-op there, so any diff is a bug.
- **Build gates:** `--diagnose` (now incl. Security import), `--test-validate`, DR
  assertion, notarization.

### 10.2 REQUIRES the live M1 (why implementation is deferred) — manual checklist

Run in order on the M1 running the current beta with real accounts. **Watch for a
keychain permission dialog at every step — any dialog at any point other than a
deliberately-broken state is a FAIL of risk #1.**

1. **Upgrade migration:** install the keychain build over the existing install → Dashboard
   opens → migration completes unattended → Keychain Access shows the expected items
   (1 API key + N IMAP + 1 SMTP) → `config.json` and every
   `~/MailWarden-upgrade-backup/*/config/config.json` contain sentinels and no real
   password substrings (grep for a known fragment).
2. **Headless filter read:** `launchctl kickstart gui/$(id -u)/com.mailwarden.filter` →
   tail `~/MailWarden/logs/spam_filter.log` → full run with IMAP logins + Claude calls;
   `keychain_status.json` shows `ok: true`; zero dialogs.
3. **Report agent:** kickstart `com.mailwarden.report` → daily report email arrives (SMTP
   secret read headlessly).
4. **Reboot test:** reboot, log in, wait ≥5 min → filter ran; no dialog pending; log shows
   at most one transient locked-skip (§4.4) followed by success.
5. **Update survival (risk #2):** build a second installer (patch bump), install over →
   kickstart both agents → reads succeed with NO prompt and NO re-migration (items
   untouched, `migration.state` still `complete`).
6. **Locked keychain:** `security lock-keychain login.keychain-db` → kickstart filter →
   run skipped (log ERROR, no mail touched), status file `locked: true`, menu bar warning
   appears, Dashboard banner names the cause → unlock → next tick recovers, warning
   clears.
7. **Kill-switch:** Settings → Stop using the Keychain → plaintext restored (verify
   file), items gone from Keychain Access, filter tick works → Re-run Keychain setup →
   back to keychain, tick works.
8. **Credential lifecycle:** edit an account's IMAP password (wrong value) → item updated
   (Keychain Access), next tick logs auth failure for that account only → fix it → clean
   run. Remove an account → its item is gone. Save a new API key → item value rotated.
9. **Uninstall:** with "delete my data" → items gone; reinstall + keep-data path → items
   survive and are picked up.
10. **Fresh install:** on a spare macOS user account: Setup Assistant end-to-end →
    plaintext never appears in `config.json` at any point (watch the file during the
    wizard), verify step passes, first tick works.
11. **GUI secret consumers:** Check-an-Email fetch, Train-folder create, Validate key —
    all work post-migration.

**Batch 5 (THE FLIP) additions — durable opt-out + re-enable:**

12. **Opt-out durability:** after step 7's "Stop using the Keychain", quit and relaunch
    the Dashboard → auto-migration does NOT re-migrate (config `migration.state` stays
    `opted_out`, backend `config`, no keychain items recreated, no dialog). The Settings
    "Keychain (advanced)" group shows the opt-out description + a single "Use the Keychain"
    button.
13. **Re-enable:** click "Use the Keychain" → migration re-runs → items reappear in Keychain
    Access, `config.json` sentinelized, `migration.state` `complete`, filter tick works;
    zero dialogs. Toggling Stop → Use the Keychain repeatedly stays clean.
14. **Fresh-install default is keychain (Batch 5):** item 10 now provisions the Keychain by
    default in the built app (the wizard sets backend `keychain` via
    `fresh_install_backend()`); confirm a fresh install lands on backend `keychain` with no
    plaintext in `config.json`, and that a keychain-write/verify failure still falls back to
    plaintext config (never a bricked first-run).

---

## 11. Batches, order, and effort

Each batch lands independently, passes the separate-model review gate + tests, and ships
**dark** (backend default `"config"`) until Batch 5. Nothing can ship half-migrated:
plaintext removal exists only behind the completed state machine, which only runs when the
backend flips, which only happens in Batch 5 after the M1 checklist.

| # | Content | Size | Gate |
|---|---|---|---|
| 1 | `keychain_store.py` ×2 (+drift guard), `secrets` config block, hydrate/strip in both loaders/savers, `keychain_status.json` writer, `_secret_errors` fail-closed checks in filter+report | ~1 session | unit+regression suites; eval byte-identical |
| 2 | `--keychain-verify` + `--set-secrets-backend` dispatch; wizard/Settings/Accounts/SMTP persistence gating; uninstall item deletion | ~1 session | unit tests; GUI paths marked for M1 |
| 3 | Migration state machine + shadow mode + kickstart verify + backup scrub; Dashboard banner, menu-bar warning, Settings keychain group, Help entry (copy drafted for Matt's review) | ~1 session | crash-state matrix tests |
| 4 | Build changes (§9): pyobjc-framework-Security, diagnose gate, DR assertion; notarized installer | ~0.5 session | --diagnose, DR gate, notarization Accepted |
| 5 | M1 execution of §10.2; then flip fresh-install default + enable auto-migration; final installer | ~0.5 session + M1 time | full checklist PASS; Matt installs |

Total ≈ 4 engineering sessions + one M1 test session.

---

## 12. Decisions made (defensible defaults, recorded so no one re-litigates blind)

1. Login keychain + file-keychain ACLs over data-protection keychain — forced by the
   two-executable Developer ID layout (§3).
2. PyObjC `pyobjc-framework-Security` over `security` CLI (partition-list dead end) and
   over ctypes (maintenance) (§5.1–5.2).
3. One item per secret; account key derived from host+username; delete+add on change (§3, §5.2).
4. Keep the interpreter's shipped identifier as-is (it is `python`, not `org.python.python`
   — see the §4.2 batch-4 correction note); add a build gate that freezes both identifiers (§4.2).
5. Fail closed = skip the entire tick on ANY unreadable secret (§7.1).
6. Fresh-install wizard falls back to plaintext config (status quo) if keychain setup
   fails, rather than blocking first-run (§6.3).
7. Scrub upgrade-backup configs in place; don't delete snapshots (§6.4).
8. Kill-switch UI ships in the public release too, relabeled non-beta ("advanced") — it is
   also the repair path (§7.2).
9. Keychain items survive keep-data uninstall; deleted only by delete-data uninstall (§7.3).

## 13. Open questions for Matt

1. **Is there any plan to change the Apple developer account / legal entity (team ID
   `6BXSAHWH29`) before or shortly after public launch?** Everything here survives
   certificate renewals and rotations within the team automatically; a team-ID change is
   the one event that needs the special two-release procedure in §4.2. If the answer is
   "no plans," nothing further is needed.

(Everything else was decided with recorded rationale in §12; all user-facing copy
introduced here is draft and goes through Matt's normal copy review in Batch 3/5.)
