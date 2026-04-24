# LDAP Signing Support — Design

**Date:** 2026-04-24
**Owner:** Justin Bollinger (@bandrel)
**Upstream:** garrettfoster13/sccmhunter

## Problem

SCCMHunter's LDAP auth path uses `ldap3`, which supports TLS channel binding (over LDAPS) but does not implement NTLMSSP message signing. Against a DC that enforces LDAP signing without LDAPS available/easy, the tool cannot bind. Users need a `--signing` mode that performs NTLM binds with LDAP signing over plain LDAP (port 389).

## Goals

- Add `--signing` (short: `-signing`) to the `find`, `mssql`, and `http` subcommands.
- Support NTLM signing with password, NTLM hashes, and Kerberos auth.
- Zero change to the consumer-side search/parsing code in attack modules.
- Keep existing `ldap3` path (plain bind, `-binding` channel binding over LDAPS) untouched.

## Non-Goals

- Implementing LDAP signing inside `ldap3` (ruled out — out of scope, requires protocol-level work).
- LDAPS + signing combo (LDAPS already provides integrity; not useful).
- Replacing `ldap3` across the codebase.

## Approach

Use `impacket.ldap.LDAPConnection` — already a transitive dep via `impacket` — for the signing path. Impacket implements NTLMSSP message signing correctly (used by NetExec, secretsdump, etc.) and supports Kerberos binds.

Wrap impacket's LDAP session in a thin adapter exposing the subset of ldap3's API that sccmhunter actually consumes, so callsites in `lib/attacks/*.py` require no changes.

## Architecture

```
CLI (-signing flag)
   ↓
Attack module (find/mssql/http) — accepts signing kwarg
   ↓
init_ldap_session(signing=True, ...)
   ↓
SignedLDAPSession  ← new adapter in lib/ldap_signed.py
   ↓
impacket.ldap.LDAPConnection (NTLM/Kerberos bind + signing)
```

## API Surface Used by Consumers

Audit of `lib/attacks/{find,mssql,http}.py` shows every LDAP consumer uses only:

1. `ldap_session.extend.standard.paged_search(search_base, search_filter=..., attributes=...)` — synchronous paged search
2. `ldap_session.entries` — list of entries after search
3. `entry.entry_to_json()` — returns JSON string of shape `{"dn": "...", "attributes": {...}}`

The adapter only needs to cover these three.

## Components

### `lib/ldap_signed.py` (new)

```
class SignedLDAPSession:
    """ldap3-compatible wrapper over impacket.ldap.LDAPConnection."""
    def __init__(self, impacket_conn):
        self._conn = impacket_conn
        self.entries = []           # populated by paged_search
        self.extend = _ExtendNS(self)  # .extend.standard.paged_search shim

class SignedEntry:
    def __init__(self, dn, attributes_dict):
        self._dn = dn
        self._attrs = attributes_dict
    def entry_to_json(self) -> str:
        return json.dumps({"dn": self._dn, "attributes": self._attrs})
```

The `paged_search` shim:
- Accepts `search_base`, `search_filter`, `attributes`, `search_scope` (default subtree)
- Calls `self._conn.search(searchBase=..., searchFilter=..., attributes=[...])`
- Converts each `SearchResultEntry` ASN.1 object into a `SignedEntry` with dn + attributes dict
- Sets `self.entries = [SignedEntry, ...]`

Attribute value decoding: match ldap3's `entry_to_json()` behavior — binary attributes (e.g., `objectSid`, `nTSecurityDescriptor`) emitted as base64; text attributes as strings; multi-valued as lists.

### `lib/ldap.py`

- Add `signing` parameter to `init_ldap_session(...)` and `init_ldap_connection(...)`.
- When `signing=True`:
  - Bail if `channel_binding=True` (mutually exclusive; log + exit).
  - Build `impacket.ldap.LDAPConnection(f'ldap://{target}', baseDN=get_dn(domain), dstIp=domain_controller)`.
  - Call `conn.login(user, password, domain, lmhash, nthash)` for NTLM, or `conn.kerberosLogin(...)` for Kerberos.
  - impacket enables signing automatically when the negotiated NTLMSSP flags include signing. Validate by checking `conn._signingRequired` / equivalent after login.
  - Wrap in `SignedLDAPSession` and return.
- When `signing=False`: existing ldap3 code path unchanged.

### CLI changes — `lib/commands/{find,mssql,http}.py`

Add to each command:
```
signing : bool = typer.Option(False, '-signing', help='Use LDAP signing (NTLM/Kerberos over plain LDAP)'),
```
Pass `signing=signing` to the respective attack class constructor.

### Attack modules — `lib/attacks/{find,mssql,http}.py`

- Add `signing=False` kwarg to `__init__`.
- Store as `self.signing`.
- Pass `signing=self.signing` into `init_ldap_session(...)`.

## Mutual Exclusion

In the CLI handler (or `init_ldap_session`): if both `signing` and `channel_binding` are set, log an error and exit. Same pattern used for existing kerberos+channel_binding guard.

## Error Handling

- impacket raises `LDAPSessionError` — catch in callers same way ldap3 errors are caught, log `str(e)`, exit.
- If `signing=True` but DC doesn't actually require signing: still works (signing is enforced client-side by impacket; server accepts).

## Testing Plan

No reliable offline test path exists for LDAP signing (protocol-level, requires live DC). Verification:

1. **Unit-ish:** construct a `SignedEntry` from a mock attribute dict; assert `entry_to_json()` output matches the shape ldap3 produces (compare to a recorded ldap3 entry json).
2. **Smoke:** `python sccmhunter.py find -u ... -p ... -d ... -dc-ip ... -signing` against Justin's live signing-required DC.
3. **Regression:** run without `-signing` against the same DC (assuming non-signing-required) to confirm ldap3 path unchanged.

Expect 1-2 iteration rounds on the adapter — ldap3's `entry_to_json()` has subtle formatting behaviors (date parsing, SID decoding) that may need matching.

## Git Flow

Two separate branches on `bandrel/sccmhunter` fork:

1. **`feat/ldap-fork-dep`** — today's already-made changes (requirements.txt + pyproject.toml + uv.lock swap to `ly4k/ldap3` git source, removal of dead `hasattr` check in `lib/ldap.py`). Commits scope: dep change only.
2. **`feat/ldap-signing`** — branched off `feat/ldap-fork-dep`. Commits scope: new signing feature (adapter + CLI flag + attack module wiring).

Both pushed to `bandrel/sccmhunter`. PR order when upstreaming: merge `feat/ldap-fork-dep` first, then `feat/ldap-signing` rebased onto updated main.

## Risks

- **Adapter output fidelity:** if `SignedEntry.entry_to_json()` diverges from ldap3's format in a way the parsers in find.py trip on, downstream errors. Mitigation: test with real DC output, compare side-by-side with ldap3 output for the same query.
- **No test DC available to Claude:** the work has to be iterated with user in the loop. Mitigation: keep PR atomic + clear so issues surface in one round.
- **impacket LDAP API churn:** impacket version bumps may shift attribute names. Pinned via existing `impacket>=0.13.0` constraint.

## Open Questions

None at spec time — git flow and Kerberos-included scope confirmed.
