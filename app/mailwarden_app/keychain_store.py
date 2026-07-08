# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Keychain secret store — one item per secret in the macOS login keychain.

DUPLICATED module: a byte-identical copy lives at
payload/MailWarden/src/keychain_store.py. The GUI package
(app/mailwarden_app) and the engine (payload/MailWarden/src) never import each
other — they share only config.json and these small self-contained helpers — so
this file is copied verbatim between the two trees. If you edit one copy, edit
the other. A drift-guard test asserts the two files are byte-identical.

Design plan: docs/keychain-design-plan.md. Ground rules this module encodes:

- Secrets are ``kSecClassGenericPassword`` items in the login keychain, one per
  secret, service ``com.strsolutions.mailwarden`` (§3). Access is via
  Security.framework through PyObjC (§5.2); the ``security`` CLI is never used.
- The ACL trusts BOTH installed executables (the app stub and the bundled
  python) by their code-signing designated requirement, so re-signed updates
  keep access (§4). Change = delete + add so the ACL is rebuilt from the
  binaries currently on disk (§5.2). Writes happen only in the GUI process.
- Everything here is DARK behind the ``secrets.backend`` config flag. When the
  flag is ``"config"`` (today's only shipped state) hydrate() returns the config
  unchanged and strip_for_save() is a pass-through, and no ``SecItem*`` call is
  reachable. Every real keychain call sits inside read_secret / write_secret /
  delete_secret, which are invoked only when the backend is ``"keychain"``.
- Import-guarded: on a machine without pyobjc-framework-Security (dev checkout,
  CI, the test suite, the offline eval) the ``Security`` import fails,
  ``available()`` returns False, and callers fall back to plaintext config
  exactly as today. No code path touches the real login keychain in tests.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Import guard. The bundled runtime ships pyobjc-framework-Security (added to
# the build alongside pyobjc-framework-ServiceManagement); a source checkout /
# CI / the test suite does not, so the import is optional and its absence just
# means available() is False and the config backend stays in force.
# ---------------------------------------------------------------------------
try:  # pragma: no cover - exercised only on a machine with the framework
    from Security import (
        SecItemAdd, SecItemCopyMatching, SecItemDelete,
        SecAccessCreate, SecTrustedApplicationCreateFromPath,
        SecKeychainSetUserInteractionAllowed,
        kSecClass, kSecClassGenericPassword,
        kSecAttrService, kSecAttrAccount, kSecAttrLabel,
        kSecValueData, kSecAttrAccess,
        kSecReturnData, kSecMatchLimit, kSecMatchLimitOne,
        kSecMatchLimitAll, kSecReturnAttributes,
        kSecUseKeychain, kSecMatchSearchList,
    )
    _SECURITY_IMPORTED = True
except Exception:  # ImportError on non-framework machines; be defensive
    _SECURITY_IMPORTED = False


SERVICE = "com.strsolutions.mailwarden"
APP_PATH = "/Applications/MailWarden.app"
PY_PATH = "/Applications/MailWarden.app/Contents/MacOS/python"

# The sentinel a config secret field holds once its value lives in the keychain.
SENTINEL = "@keychain:v1"
SENTINEL_PREFIX = "@keychain:"

# Top-level config key for the per-install self-mail HMAC secret (Wave 6).
SELF_MAIL_SECRET_KEY = "self_mail_secret"

# Fixed kSecAttrAccount values / prefixes for the derived item keys (§3).
ACCOUNT_ANTHROPIC = "anthropic-api-key"
ACCOUNT_SELF_MAIL = "self-mail-secret"

# OSStatus codes we branch on (§5.2).
errSecSuccess = 0
errSecItemNotFound = -25300
errSecDuplicateItem = -25299
errSecAuthFailed = -25293
errSecInteractionNotAllowed = -25308


class KeychainError(Exception):
    """A Security.framework call returned a non-success, non-recoverable status."""

    def __init__(self, op: str, status: int):
        self.op = op
        self.status = status
        super().__init__(f"{op} failed: OSStatus {status}")


class KeychainLocked(Exception):
    """A read was denied because the keychain is locked or the ACL rejected us
    (errSecInteractionNotAllowed / errSecAuthFailed). Callers distinguish this
    from a plain missing item so the engine can fail closed (§7.1)."""

    def __init__(self, status: int):
        self.status = status
        super().__init__(f"keychain locked/denied: OSStatus {status}")


def available() -> bool:
    """True only when the Security.framework wrappers imported. When False the
    config backend is used and no keychain call is possible."""
    return _SECURITY_IMPORTED


# ---------------------------------------------------------------------------
# Deterministic item keys (§3). Derived purely from config fields so the
# sentinel needs no stored reference and edits map cleanly onto add/delete.
# ---------------------------------------------------------------------------

def api_key_account() -> str:
    return ACCOUNT_ANTHROPIC


def self_mail_account() -> str:
    return ACCOUNT_SELF_MAIL


def imap_account(imap_host: str, username: str) -> str:
    return "imap|%s|%s" % ((imap_host or "").strip().lower(),
                           (username or "").strip().lower())


def smtp_account(host: str, username: str) -> str:
    return "smtp|%s|%s" % ((host or "").strip().lower(),
                           (username or "").strip().lower())


def label_for(account_key: str, username: str = "") -> str:
    """Human-facing Keychain Access display label (kSecAttrLabel)."""
    if account_key == ACCOUNT_ANTHROPIC:
        return "MailWarden — Anthropic API key"
    if account_key == ACCOUNT_SELF_MAIL:
        return "MailWarden — self-mail signing key"
    if account_key.startswith("imap|"):
        return "MailWarden IMAP — %s" % (username or account_key)
    if account_key.startswith("smtp|"):
        return "MailWarden SMTP — %s" % (username or account_key)
    return "MailWarden — %s" % account_key


# ---------------------------------------------------------------------------
# No-UI discipline for headless processes (§4.3). The engine calls this once at
# startup so a locked keychain / ACL miss returns an error code instead of
# blocking a launchd tick behind an invisible dialog.
# ---------------------------------------------------------------------------

def set_user_interaction_allowed(allowed: bool) -> None:
    if not _SECURITY_IMPORTED:
        return
    try:
        SecKeychainSetUserInteractionAllowed(bool(allowed))
    except Exception:
        # Never let the UI-suppression toggle crash a tick; a failure here just
        # means the default (interaction allowed) stands, and a locked-keychain
        # read still fails closed on the status code below.
        pass


# ---------------------------------------------------------------------------
# Raw item operations. These are the ONLY functions that touch SecItem*; they
# are called only when the active backend is "keychain" (never in config mode),
# which is what makes the dark-ship guarantee provable.
# ---------------------------------------------------------------------------

def _access():
    """Build a SecAccess trusting BOTH installed executables (§4.1/§5.2)."""
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


def write_secret(account_key: str, label: str, value: str, keychain=None) -> None:
    """Create-or-replace one secret item. Delete+add (never SecItemUpdate) so the
    ACL is always rebuilt from the CURRENT installed binaries (§5.2). GUI-only in
    production; ``keychain`` is a test-only throwaway-keychain ref (§5.2)."""
    if not _SECURITY_IMPORTED:
        raise KeychainError("write_secret (framework absent)", 0)
    delete_secret(account_key, missing_ok=True, keychain=keychain)
    attrs = {
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: SERVICE,
        kSecAttrAccount: account_key,
        kSecAttrLabel: label,
        kSecValueData: value.encode("utf-8"),
        kSecAttrAccess: _access(),
    }
    if keychain is not None:
        attrs[kSecUseKeychain] = keychain
    status, _ = SecItemAdd(attrs, None)
    if status != errSecSuccess:
        raise KeychainError("SecItemAdd", status)


def read_secret(account_key: str, keychain=None) -> "str | None":
    """Return the secret string, or None when the item is absent. Raises
    KeychainLocked on a locked keychain / ACL denial so callers can fail closed
    (§7.1); any other failure raises KeychainError."""
    if not _SECURITY_IMPORTED:
        raise KeychainError("read_secret (framework absent)", 0)
    query = {
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: SERVICE,
        kSecAttrAccount: account_key,
        kSecReturnData: True,
        kSecMatchLimit: kSecMatchLimitOne,
    }
    if keychain is not None:
        query[kSecMatchSearchList] = [keychain]
    status, data = SecItemCopyMatching(query, None)
    if status == errSecItemNotFound:
        return None
    if status in (errSecInteractionNotAllowed, errSecAuthFailed):
        raise KeychainLocked(status)
    if status != errSecSuccess:
        raise KeychainError("SecItemCopyMatching", status)
    return bytes(data).decode("utf-8")


def delete_secret(account_key: str, missing_ok: bool = False, keychain=None) -> None:
    if not _SECURITY_IMPORTED:
        raise KeychainError("delete_secret (framework absent)", 0)
    query = {kSecClass: kSecClassGenericPassword,
             kSecAttrService: SERVICE, kSecAttrAccount: account_key}
    if keychain is not None:
        query[kSecMatchSearchList] = [keychain]
    status = SecItemDelete(query)
    if status == errSecItemNotFound and missing_ok:
        return
    if status not in (errSecSuccess, errSecItemNotFound):
        raise KeychainError("SecItemDelete", status)


# ---------------------------------------------------------------------------
# Backend helpers and config integration (§5.3).
# ---------------------------------------------------------------------------

def backend_of(config: dict) -> str:
    """The active secrets backend for this config ("config" | "keychain")."""
    if not isinstance(config, dict):
        return "config"
    sec = config.get("secrets") or {}
    b = sec.get("backend")
    return b if b in ("config", "keychain") else "config"


def migration_state(config: dict) -> str:
    sec = config.get("secrets") or {}
    mig = sec.get("migration") or {}
    return mig.get("state", "none")


def revert_epoch(config: dict) -> int:
    """Monotonic counter bumped by every revert-to-config (§7.2). An in-flight
    migration snapshots it at start and aborts cleanly if it changes mid-run, so
    a "Stop using the Keychain" pressed during a background repair/re-run can
    never be silently undone by the still-running migration thread (defect D3)."""
    sec = config.get("secrets") or {}
    mig = sec.get("migration") or {}
    try:
        return int(mig.get("revert_epoch", 0))
    except (TypeError, ValueError):
        return 0


def hydrate(config: dict) -> dict:
    """Replace keychain-backed secret fields in ``config`` with their real
    values, in memory (§5.3). No-op — the identical object is returned — when the
    backend is "config", which keeps runtime behavior byte-for-byte today's.

    Only sentinel values ("@keychain:…") are hydrated in the normal (complete)
    case. During an in-progress migration (state != "complete") the loader also
    tries the keychain for still-plaintext fields and falls back to the plaintext
    on a read failure (shadow mode, §6.2) so filtering never breaks mid-migration.

    EVERY keychain read failure is recorded on the returned dict under the
    non-persisted key ``_secret_errors`` (stripped on save) — including shadow-
    mode failures where the plaintext fallback keeps the run alive. Each record
    is ``{"key", "reason": "locked"|"missing"|"error", "shadow": bool}``:
    ``shadow`` True means a usable plaintext fallback was returned (the run can
    proceed but the keychain did NOT serve this secret — tick-verify must not
    pass, §6.2); shadow False means no usable value exists (fail closed, §7.1).
    A locked keychain is recorded, never raised, so loading config for a
    non-secret purpose still works.
    """
    if not isinstance(config, dict):
        return config
    if backend_of(config) != "keychain":
        return config

    shadow = migration_state(config) != "complete"
    errors: list = []

    def resolve(value, account_key):
        is_sentinel = isinstance(value, str) and value.startswith(SENTINEL_PREFIX)
        # Complete mode: only hydrate sentinels; leave anything else untouched.
        if not is_sentinel and not shadow:
            return value
        # Shadow mode on a still-empty plaintext field: nothing to read.
        if not is_sentinel and shadow and not (isinstance(value, str) and value):
            return value

        def record(reason):
            # "shadow": True IFF a usable plaintext fallback is being returned
            # (non-sentinel field in the shadow window). A failed sentinel read
            # has no fallback anywhere, so it is always a hard (non-shadow)
            # error, even mid-migration.
            errors.append({"key": account_key, "reason": reason,
                           "shadow": not is_sentinel})

        try:
            got = read_secret(account_key)
        except KeychainLocked:
            record("locked")
            return value
        except KeychainError:
            record("error")
            return value
        if got is None:
            record("missing")
            return value
        return got

    anthro = config.get("anthropic")
    if isinstance(anthro, dict) and "api_key" in anthro:
        anthro["api_key"] = resolve(anthro.get("api_key"), api_key_account())

    smtp = config.get("smtp")
    if isinstance(smtp, dict) and "password" in smtp:
        smtp["password"] = resolve(
            smtp.get("password"),
            smtp_account(smtp.get("host", ""), smtp.get("username", "")))

    for acct in config.get("accounts", []) or []:
        if isinstance(acct, dict) and "password" in acct:
            acct["password"] = resolve(
                acct.get("password"),
                imap_account(acct.get("imap_host", ""), acct.get("username", "")))

    # self_mail_secret is deliberately NOT hydrated here: it is a lazily-generated
    # secret read through get_or_create_self_mail_secret (its own backend-aware
    # path), never consumed from the config dict, so hydrating it would risk
    # returning the sentinel string to that reader when the item is absent.
    #
    # D5: at the keychain backend a CLEARED (empty) Anthropic API key is a HARD,
    # fail-closed condition — the tick must SKIP, not run the untested half-mode
    # (IMAP logins + deterministic junking + a per-message AI auth error) that
    # §7.1's all-or-nothing rule rejects. Recorded as a non-shadow error so
    # hard_secret_errors() fails the run closed and status_record() surfaces it
    # to the banner. INERT at the config backend (this whole function returned
    # early above), so an empty key there keeps today's behavior — dark ship.
    resolved_api = anthro.get("api_key") if isinstance(anthro, dict) else None
    if isinstance(resolved_api, str) and resolved_api.strip() == "":
        errors.append({"key": api_key_account(), "reason": "empty",
                       "shadow": False})
    config["_secret_errors"] = errors
    return config


def strip_for_save(config: dict) -> dict:
    """Return a copy of ``config`` safe to serialize when the backend is
    "keychain": every secret field is replaced with the sentinel and any
    non-persisted ``_``-prefixed key is dropped (§5.3). This is what closes the
    plaintext-leak paths (e.g. the engine's EULA-merge save) by construction.

    No-op — the SAME object is returned, so the on-disk bytes are unchanged —
    when the backend is "config". The strip NEVER writes to the keychain; GUI
    flows that change a secret call write_secret() explicitly first, then save.

    SHADOW WINDOW (§6.2): while migration.state != "complete", plaintext must
    SURVIVE in config.json — it is the fallback that keeps filtering alive if a
    launchd keychain read fails during steps 3-4, and step 4's scrub is the ONLY
    thing allowed to remove it. So the sentinelize pass below runs solely at
    state "complete"; an earlier save still drops the in-memory ``_``-prefixed
    keys but leaves every secret field exactly as loaded.
    """
    if not isinstance(config, dict):
        return config
    if backend_of(config) != "keychain":
        return config

    import copy
    clone = copy.deepcopy(config)
    for k in [k for k in clone if isinstance(k, str) and k.startswith("_")]:
        del clone[k]

    if migration_state(config) != "complete":
        return clone

    def sentinelize(v):
        if isinstance(v, str) and v and not v.startswith(SENTINEL_PREFIX):
            return SENTINEL
        return v

    anthro = clone.get("anthropic")
    if isinstance(anthro, dict) and "api_key" in anthro:
        anthro["api_key"] = sentinelize(anthro["api_key"])
    smtp = clone.get("smtp")
    if isinstance(smtp, dict) and "password" in smtp:
        smtp["password"] = sentinelize(smtp["password"])
    for acct in clone.get("accounts", []) or []:
        if isinstance(acct, dict) and "password" in acct:
            acct["password"] = sentinelize(acct["password"])
    if SELF_MAIL_SECRET_KEY in clone:
        clone[SELF_MAIL_SECRET_KEY] = sentinelize(clone.get(SELF_MAIL_SECRET_KEY))
    return clone


def hard_secret_errors(config: dict) -> list:
    """The subset of ``_secret_errors`` with NO usable fallback value in memory
    (non-shadow). These are the failures that must fail a run closed (§7.1);
    shadow-flagged entries mean the plaintext fallback kept the secret usable
    and the run may proceed — though tick-verify must still see them (ok:false
    in status_record) so a never-working keychain can never reach the scrub."""
    errors = config.get("_secret_errors") or []
    return [e for e in errors if not e.get("shadow")]


def status_record(config: dict, pid_context: str) -> dict:
    """The keychain_status.json payload the engine writes each keychain-backed run
    (§6.2/§7.1): booleans and key names only, never secret values. ``ok`` is True
    ONLY when every keychain read genuinely succeeded — a shadow-mode plaintext
    fallback still reports ok:false (with shadow_fallback:true), so Batch 3's
    tick-verify gate can never advance to the scrub on a keychain that has not
    actually served every secret. Plain errors (neither locked nor missing) get
    their own key list so the Dashboard banner can categorize them."""
    errors = config.get("_secret_errors") or []
    return {
        "ts": _now_iso(),
        "backend": backend_of(config),
        "ok": not errors,
        "missing": [e.get("key") for e in errors if e.get("reason") == "missing"],
        "locked": any(e.get("reason") == "locked" for e in errors),
        "errors": [e.get("key") for e in errors if e.get("reason") == "error"],
        # D5: a CLEARED (empty) required key — distinct cause so the banner can
        # say "no API key configured" instead of "unreadable".
        "empty": [e.get("key") for e in errors if e.get("reason") == "empty"],
        "shadow_fallback": any(e.get("shadow") for e in errors),
        "pid_context": pid_context,
    }


def _now_iso() -> str:
    from datetime import datetime
    return datetime.now().isoformat()


# ===========================================================================
# Batch 2 — CLI verify, GUI persistence gating, and uninstall.
#
# Everything below stays DARK behind the same secrets.backend flag: the pure
# helpers never touch a raw op, and every function that CAN write/read/delete
# an item is either backend-gated (returns immediately at the "config" backend)
# or reachable only from a code path the migration state machine (Batch 3) and
# the M1 checklist (Batch 5) light up. No SecItem* CALL is added outside the
# raw ops except delete_all_items()'s enumeration (a genuine new raw primitive;
# see the drift-guard's allowed set).
# ===========================================================================

# ---------------------------------------------------------------------------
# Pure decision helpers (no IO) — safe to call at any backend, unit-tested.
# ---------------------------------------------------------------------------

def _present(value) -> bool:
    """True for a non-empty string secret field (a configured secret). An empty
    field means 'no secret here' — never a keychain item."""
    return isinstance(value, str) and value.strip() != ""


def expected_account_keys(config: dict) -> list:
    """The item keys the keychain should hold for THIS config (§3): one per
    non-empty secret field — the API key, the SMTP password, and each account's
    IMAP password (deduped, so a shared mailbox collapses to one key). A field
    holding the sentinel counts (already migrated); an empty field does not.

    This is the single source of truth shared by --keychain-verify (§6.2 step 2),
    the fresh-install provisioner (§6.3), and — in Batch 3 — the migration
    writer, so all three agree on exactly which items must exist. self_mail_secret
    is intentionally excluded: it is lazily minted through its own backend-aware
    path, not a migrated config field, so it may legitimately be absent."""
    if not isinstance(config, dict):
        return []
    keys: list = []
    anthro = config.get("anthropic") or {}
    if _present(anthro.get("api_key")):
        keys.append(api_key_account())
    smtp = config.get("smtp") or {}
    if _present(smtp.get("password")):
        keys.append(smtp_account(smtp.get("host", ""), smtp.get("username", "")))
    for acct in config.get("accounts") or []:
        if isinstance(acct, dict) and _present(acct.get("password")):
            k = imap_account(acct.get("imap_host", ""), acct.get("username", ""))
            if k not in keys:
                keys.append(k)
    return keys


def key_in_use(account_key: str, accounts) -> bool:
    """True when any account in ``accounts`` still derives ``account_key`` — the
    shared-mailbox guard (§3): two accounts with the same (imap_host, username)
    share ONE item, so removing/editing one must NOT delete the item the other
    still needs."""
    for a in accounts or []:
        if isinstance(a, dict) and \
                imap_account(a.get("imap_host", ""), a.get("username", "")) == account_key:
            return True
    return False


def clear_unresolved_sentinels(config: dict) -> list:
    """Revert helper (§7.2). After a revert hydration, any secret field STILL
    holding a sentinel was unreadable from the keychain; blank it to "" and return
    the derived account keys of the blanked fields so the caller can warn the
    owner to re-enter them. Also drops any non-persisted ``_``-prefixed key that
    hydrate left on the dict. PURE (no keychain IO) — walks the same three secret
    slots hydrate does. Mutates ``config`` in place."""
    if not isinstance(config, dict):
        return []
    blanked: list = []

    def clear(container, field, account_key):
        v = container.get(field)
        if isinstance(v, str) and v.startswith(SENTINEL_PREFIX):
            container[field] = ""
            blanked.append(account_key)

    anthro = config.get("anthropic")
    if isinstance(anthro, dict) and "api_key" in anthro:
        clear(anthro, "api_key", api_key_account())
    smtp = config.get("smtp")
    if isinstance(smtp, dict) and "password" in smtp:
        clear(smtp, "password",
              smtp_account(smtp.get("host", ""), smtp.get("username", "")))
    for acct in config.get("accounts", []) or []:
        if isinstance(acct, dict) and "password" in acct:
            clear(acct, "password",
                  imap_account(acct.get("imap_host", ""), acct.get("username", "")))
    # The per-install self-mail HMAC secret is auto-minted, not owner-entered, so
    # a sentinel value here must be BLANKED (never left as the literal sentinel,
    # which the config-backend getter would otherwise return verbatim as the HMAC
    # key — silently re-opening the Wave-6 marker-spoofing bypass). Blank so the
    # getter re-mints a fresh secret on next use; do NOT add it to `blanked` (no
    # owner re-entry is needed for it).
    sm = config.get(SELF_MAIL_SECRET_KEY)
    if isinstance(sm, str) and sm.startswith(SENTINEL_PREFIX):
        config[SELF_MAIL_SECRET_KEY] = ""
    for k in [k for k in config if isinstance(k, str) and k.startswith("_")]:
        del config[k]
    return blanked


# Durable OPT-OUT marker left by EVERY "Stop using the Keychain" revert (§7.2).
# The backend is flipped back to "config" and the user has made a lasting choice
# to stay on the settings-file backend. This is NOT one of the state-machine's
# own steps — the driver never advances it — and auto-migration treats it as
# INERT (migration_should_run returns False for it) so an opted-out user is never
# silently re-migrated. Only an explicit "Use the Keychain" re-enable (the force
# path) leaves it. It also keeps keychain_items_may_exist() True so a later
# delete-data uninstall still cleans any orphaned items — covering BOTH a
# KEPT-branch revert (unreadable items deliberately not deleted) AND the crash
# window of a clean revert (items were about to be deleted but the process died
# before delete_all_items ran).
STATE_OPTED_OUT = "opted_out"


def revert_config_to_plaintext(config: dict) -> list:
    """Shared kill-switch / revert core (§7.2), used by the CLI escape hatch and
    the Dashboard "Stop using the Keychain" button so the two paths behave
    identically. The ``config`` passed in is already HYDRATED by load_config —
    readable items sit as plaintext in their fields; unreadable ones still hold
    the sentinel. This: blanks the unreadable sentinels (and returns their derived
    account keys so the caller can warn the owner to re-enter them), drops
    hydrate's ``_``-prefixed keys, and flips ``secrets.backend`` to "config".

    ``secrets.migration.state`` goes to the durable ``STATE_OPTED_OUT`` marker in
    BOTH outcomes — a clean revert (every secret recovered; the caller then
    deletes the now-orphaned items) AND a KEPT revert (some unreadable, items
    kept). Unifying them fixes the old asymmetry: a clean revert used to land on
    "none", which auto-migration (Batch 5) would re-migrate, and a KEPT revert
    used to stick on "reverted_kept" forever. Now both are inert to
    auto-migration and both keep keychain_items_may_exist() True so uninstall
    cleans any orphans (a clean revert's items may still exist if the process
    crashed before the caller's delete). The clean/kept distinction survives only
    in the returned ``unreadable`` list (the re-entry warning). PURE — no keychain
    IO; the caller does any delete."""
    unreadable = clear_unresolved_sentinels(config)
    sec = config.setdefault("secrets", {})
    sec["backend"] = "config"
    mig = sec.setdefault("migration", {})
    mig["state"] = STATE_OPTED_OUT
    # D3: bump the revert epoch so any migration thread still running in this
    # process (a background repair/re-run) detects the revert on its next
    # iteration and aborts cleanly instead of silently resurrecting the keychain
    # backend it just left. Atomic with the backend flip (same locked write).
    try:
        mig["revert_epoch"] = int(mig.get("revert_epoch", 0)) + 1
    except (TypeError, ValueError):
        mig["revert_epoch"] = 1
    return unreadable


def keychain_items_may_exist(config: dict) -> bool:
    """True when login-keychain items may exist for this install. Gates the
    delete-data uninstall's item cleanup (§7.3, carry-over B) so orphans left by
    a partial migration (crash mid-flight) or ANY revert are still removed. INERT
    (False) in a config-backend beta that never migrated: backend "config" +
    migration.state "none" => False, so no SecItem enumeration is reachable. Every
    revert now leaves the durable STATE_OPTED_OUT marker (!= "none") => True, so a
    clean revert whose caller crashed before delete_all_items still gets cleaned
    (Batch-5 §7.3 crash-window fix), and a KEPT revert's deliberately-retained
    items are cleaned too. A mid-migration crash leaves items_written/etc. =>
    True."""
    if not isinstance(config, dict):
        return False
    if backend_of(config) == "keychain":
        return True
    return migration_state(config) != "none"


# ---------------------------------------------------------------------------
# Verify (§6.2 step 2). Reads every expected item; returns booleans + key names
# only, never values. Delegates to read_secret (a raw op) so no SecItem* call is
# added here. Safe to call in-process (no UI-suppression side effect — the
# headless --keychain-verify entry suppresses UI itself).
# ---------------------------------------------------------------------------

def verify_keys(config: dict, keys=None) -> dict:
    """Read every expected account key and categorize the result:
    ``{"ok", "missing": [...], "locked": bool, "errors": [...]}``. ``ok`` is True
    only when every expected item read back cleanly. Never returns or logs a
    secret value. Reads regardless of the backend flag (verify runs at migration
    step 2, while the backend is still "config" but the items already exist).

    ``keys`` (key-name strings only, never secret values) overrides derivation
    from ``config`` — the crux of the fresh-install fix: the wizard saves config
    AFTER provisioning, so a subprocess re-deriving from disk would see an empty
    config and pass vacuously. The wizard therefore passes the in-memory
    expected keys explicitly. When ``keys`` is None the on-disk config is used
    (the migration/upgrade path, where config.json already holds the secrets)."""
    missing: list = []
    errors: list = []
    locked = False
    for key in (keys if keys is not None else expected_account_keys(config)):
        try:
            got = read_secret(key)
        except KeychainLocked:
            locked = True
            continue
        except KeychainError:
            errors.append(key)
            continue
        if got is None:
            missing.append(key)
    return {"ok": not missing and not errors and not locked,
            "missing": missing, "locked": locked, "errors": errors}


# ---------------------------------------------------------------------------
# GUI-only writers (§8). Every one is backend-gated: a pure pass-through at the
# "config" backend (the dark default), so today's plaintext persistence is
# byte-identical. Callers set the plaintext config field and save separately;
# strip_for_save() sentinelizes it on save once migration.state == "complete".
# ---------------------------------------------------------------------------

def write_configured_secrets(config: dict) -> None:
    """Write every currently-plaintext configured secret in ``config`` into the
    keychain (fresh-install provisioning §6.3, and — Batch 3 — migration step 1).
    NOT backend-gated: the caller has already decided keychain is in force. Skips
    empty fields and fields already holding the sentinel. GUI-process only."""
    anthro = config.get("anthropic") or {}
    v = anthro.get("api_key")
    if isinstance(v, str) and v and not v.startswith(SENTINEL_PREFIX):
        k = api_key_account()
        write_secret(k, label_for(k), v)
    smtp = config.get("smtp") or {}
    v = smtp.get("password")
    if isinstance(v, str) and v and not v.startswith(SENTINEL_PREFIX):
        k = smtp_account(smtp.get("host", ""), smtp.get("username", ""))
        write_secret(k, label_for(k, smtp.get("username", "")), v)
    for acct in config.get("accounts") or []:
        if not isinstance(acct, dict):
            continue
        v = acct.get("password")
        if isinstance(v, str) and v and not v.startswith(SENTINEL_PREFIX):
            k = imap_account(acct.get("imap_host", ""), acct.get("username", ""))
            write_secret(k, label_for(k, acct.get("username", "")), v)


def sync_secret(config: dict, account_key: str, label: str, value: str) -> None:
    """Persist ONE changed secret (Settings API key, an account's IMAP password,
    SMTP) to the keychain when keychain-backed; a no-op at the "config" backend.
    ``value`` must be the real typed secret — an empty or already-sentinel value
    is ignored (nothing to store; the field save handles clearing)."""
    if backend_of(config) != "keychain":
        return
    if not isinstance(value, str) or not value or value.startswith(SENTINEL_PREFIX):
        return
    write_secret(account_key, label, value)


def forget_secret(config: dict, account_key: str, remaining_accounts=None) -> None:
    """Delete an account's IMAP item when keychain-backed and no OTHER remaining
    account still derives the same key (shared-mailbox guard, §3); a no-op at the
    "config" backend. Pass the account list WITHOUT the row being removed/edited
    as ``remaining_accounts``."""
    if backend_of(config) != "keychain":
        return
    if key_in_use(account_key, remaining_accounts):
        return
    delete_secret(account_key, missing_ok=True)


# ---------------------------------------------------------------------------
# Fresh-install provisioning (§6.3 / §12.6). DARK until Batch 5 flips the
# default backend: gated on the config's own backend being "keychain", which is
# "config" today, so the wizard's plaintext save is byte-identical. When lit, it
# writes the secrets, spawns the OTHER code identity to prove a headless read
# (the faithful ACL test), and on ANY failure falls back to plaintext config so
# first-run is never blocked.
# ---------------------------------------------------------------------------

def spawn_keychain_verify(config: dict, timeout: float = 10.0) -> dict:
    """Spawn the bundled python as the OTHER code identity to run
    ``launcher.py --keychain-verify`` (§6.2 step 2) — the faithful test of the ACL
    path the launchd agents use, because keychain trust is evaluated against the
    main executable, not the script.

    The expected item KEYS are derived from the IN-MEMORY ``config`` and handed to
    the subprocess over stdin (never argv — the keys embed usernames/hosts). This
    is essential on a fresh install, where config.json is not written until AFTER
    provisioning: a subprocess re-deriving keys from disk would find an empty
    config and report ok vacuously with zero reads. Only key NAMES cross the pipe,
    never secret values. Returns the parsed JSON verdict, or an ok:false verdict
    on timeout / spawn / parse failure. M1/GUI-only (real /Applications paths)."""
    import subprocess
    import json as _json
    launcher = APP_PATH + "/Contents/Resources/launcher.py"
    payload = _json.dumps({"keys": expected_account_keys(config)})
    try:
        proc = subprocess.run(
            [PY_PATH, launcher, "--keychain-verify", "--keys-from-stdin"],
            input=payload, capture_output=True, text=True, timeout=timeout)
        out = (proc.stdout or "").strip()
        return _json.loads(out) if out else {"ok": False, "missing": [],
                                             "locked": False, "spawn_error": True}
    except Exception:
        return {"ok": False, "missing": [], "locked": False, "spawn_error": True}


def _fall_back_to_config(config: dict) -> None:
    """Roll a failed keychain provisioning back to the plaintext-config backend
    (§6.3): keep the real secrets in the config fields (they get written 0600 as
    today), flag the backend "config", and best-effort delete any partial items
    so nothing is left half-migrated."""
    sec = config.setdefault("secrets", {})
    sec["backend"] = "config"
    sec.setdefault("migration", {})["state"] = "none"
    # Never leave a sentinel self-mail secret behind on the config backend (same
    # Wave-6 hole clear_unresolved_sentinels guards): blank it so the getter
    # re-mints a real secret.
    sm = config.get(SELF_MAIL_SECRET_KEY)
    if isinstance(sm, str) and sm.startswith(SENTINEL_PREFIX):
        config[SELF_MAIL_SECRET_KEY] = ""
    try:
        if available():
            delete_all_items()
    except Exception:
        pass


def provision_fresh_install(config: dict, verifier=None) -> dict:
    """Fresh-install wizard hook (§6.3). No-op returning immediately when the
    config's backend is "config" — the dark default — so today's plaintext wizard
    save is byte-identical. When the backend is "keychain" (Batch 5+): write every
    configured secret, spawn the headless verify, and on success mark migration
    complete (so save sentinelizes). On a missing framework, a write failure, or a
    verify failure, fall back to plaintext config and NEVER block first run.

    ``verifier`` is an injection seam for tests: a callable ``(config) -> verdict
    dict``; production uses the real subprocess spawn. Returns a small result dict
    ``{"backend", "provisioned", "reason"?}`` for the caller's log line."""
    if backend_of(config) != "keychain":
        return {"backend": "config", "provisioned": False}
    if not available():
        _fall_back_to_config(config)
        return {"backend": "config", "provisioned": False,
                "reason": "framework_absent"}
    try:
        write_configured_secrets(config)
    except Exception as e:  # noqa: BLE001
        # §12.6: NEVER block first run. Catch ANY failure — not only
        # KeychainError/KeychainLocked but an unexpected objc.error or other
        # low-level fault from a write — and fall back to plaintext config.
        _fall_back_to_config(config)
        return {"backend": "config", "provisioned": False,
                "reason": "write_failed", "error": f"{type(e).__name__}: {e}"}
    verify = verifier or (lambda cfg: spawn_keychain_verify(cfg))
    try:
        verdict = verify(config)
    except Exception as e:  # noqa: BLE001
        _fall_back_to_config(config)
        return {"backend": "config", "provisioned": False,
                "reason": "verify_failed", "error": f"{type(e).__name__}: {e}"}
    if verdict.get("ok"):
        config.setdefault("secrets", {}).setdefault(
            "migration", {})["state"] = "complete"
        return {"backend": "keychain", "provisioned": True}
    _fall_back_to_config(config)
    return {"backend": "config", "provisioned": False, "reason": "verify_failed"}


# ---------------------------------------------------------------------------
# Uninstall (§7.3). Enumerate every MailWarden item by service and delete each,
# so a delete-data uninstall removes the secrets too. Gated by the CALLER on
# backend == "keychain" so no SecItem* call is reachable at the "config" backend
# (dark ship). Enumeration is a genuine new raw primitive — the ONLY SecItem*
# CALL added outside read/write/delete_secret; the drift-guard allows it.
# ---------------------------------------------------------------------------

def delete_all_items() -> int:
    """Delete every MailWarden generic-password item in the login keychain,
    regardless of the current config (§7.3, delete-data uninstall). Enumerates by
    service, then deletes each via delete_secret. Returns the number removed.
    Requires the framework (raises KeychainError if absent, like the raw ops)."""
    if not _SECURITY_IMPORTED:
        raise KeychainError("delete_all_items (framework absent)", 0)
    query = {
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: SERVICE,
        kSecReturnAttributes: True,
        kSecMatchLimit: kSecMatchLimitAll,
    }
    status, items = SecItemCopyMatching(query, None)
    if status == errSecItemNotFound:
        return 0
    if status != errSecSuccess:
        raise KeychainError("SecItemCopyMatching(all)", status)
    count = 0
    for it in (items or []):
        acct = it.get(kSecAttrAccount) if hasattr(it, "get") else None
        if acct:
            delete_secret(acct, missing_ok=True)
            count += 1
    return count
