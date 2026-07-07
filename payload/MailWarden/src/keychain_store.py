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
        "shadow_fallback": any(e.get("shadow") for e in errors),
        "pid_context": pid_context,
    }


def _now_iso() -> str:
    from datetime import datetime
    return datetime.now().isoformat()
