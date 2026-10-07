# Transactional storage contract

Storage.transaction() yields UnitOfWork. Synchronous Authlib work runs in a worker thread inside a transaction; ContextVar isolates the current unit per operation.

## Required production guarantees

- Durable, **serializable cross-worker/process transactions**. A process-local lock is insufficient. Prove database transaction or locked atomic-file semantics under the real deployment model.
- Normal return commits; every exception, including write/commit failure, rolls back **all** entity writes. HTTP success cannot escape before durable commit. Storage failure discards generated credentials and returns generic 503.
- Code lookup/validation, family persistence and code deletion form one transaction: exactly one concurrent correct exchange succeeds. Wrong verifier/client/redirect/resource preserves the code. Failed persistence preserves old state.
- Refresh lookup, binding/replay checks, replacement and used-digest tombstone insertion form one transaction. No partial new token family may survive failure.
- **OAuth error responses are normal returns:** commit replay revocation/pruning even if HTTP400. Rolling back every error response would resurrect replayed families. Unexpected exceptions do roll back.
- Check correct client/resource **before** replay-family revocation. A concurrent replay invalidates the sole issued successor too; serialize refreshes. No grace-window retry is provided.
- Preserve original created_at/absolute expires_at. Clamp access expiry to remaining lifetime. At rotation cap revoke the family; never discard old replay digests while keeping it active.
- Capacity check and insert occur under the same transaction. Prune expired codes, consents and families before evaluating clients. Client inactivity uses `last_used_at` (falling back to `issued_at`); live codes, pending authorization or unrevoked unexpired grants protect clients regardless of registration age. Successful validated DCR use atomically replaces the client with updated activity time. Missing/deleted clients cannot leave valid access credentials.
- Persist only digests for codes/access/refresh/consent tickets. Pending state contains public authorization input, state and challenge, never verifier or bearer credentials. Protect storage/backups as private data.
- Constant-time direct digest comparisons; digest-indexed database lookup is appropriate for high-entropy credentials. Index client IDs and all current/used digests with uniqueness constraints.
- Coordinate authoritative identity version/incarnation checks with account writes. Stable ID alone does not protect delete/recreate or reset races.

## Records and operations

Client: exact redirects, scopes/grants, name, ID/issued time, optional `last_used_at` and `metadata_origin`. Code: digest, subject/version, client/source/redirect/resource/scope/challenge/expiry. PendingConsent: ticket digest, subject/version, authorization parameters with explicit resolved scope/redirect and expiry. Grant: family ID, subject/version, client/source/resource/narrowed scope, original/absolute/access times, current access/refresh digests, used-refresh tuple, revoked flag. `client_source` is `dcr` or `cimd`; source mismatches must not validate credentials. CIMD Client objects are request-local/cache records, never persistent registrations. Access validation rejects unknown sources and missing DCR registrations even if an adapter accidentally leaves an orphaned grant.

`find_token()` accepts only `access_token` and `refresh_token` (`TokenKind`). Unknown kinds must raise rather than silently selecting refresh lookup. Authlib's revocation endpoint handles valid hint fallback using these two explicit kinds.

UnitOfWork exposes explicit get/put/delete/list methods, token-digest lookup and pruning; the contract does not depend on a host database schema. Immutable records support atomic replacement. List methods materialize bounded state in v0.1; production should use indexed access inside these operations. Capacity and rotation limits bound replay growth.

## MemoryStorage limitation

**Development/single-process only.** One RLock serializes transactions. Each uses a private deep copy, installed only on successful exit. Scans/copies grow with state; production needs an indexed durable adapter. Separate workers do not share memory.

snapshot/from_snapshot are trusted fixture export/reload, not an import API or durable database. Never load untrusted snapshots. Tests verify digest secrecy, reload, pruning, concurrent code/refresh operations and commit failures for registration/consent/code issuance/exchange/refresh.

Snapshots now write schema 2 and accept schemas 1 and 2. Old clients default `last_used_at=None` and `metadata_origin=None`; old codes/grants default source `dcr`. Other schema versions fail explicitly. Production adapters must make an equivalent migration when adopting the new record fields. Switching modes changes acceptance, not destructive storage migration; regular expiry and explicit administration still apply.

Pending consent without an explicit resolved scope or redirect is rejected at confirmation. Users must restart authorization for such legacy tickets; defaults must never be recomputed from changed client metadata after consent was displayed.

Do not perform unbounded network work in a storage lock. Identity's authoritative lookup is synchronous. Render/decision callbacks are outside transactions; completion revalidates the pending consent and current subject before issuing a code. Host login/identity can share the same durable account transaction strategy for stronger account-write coordination.

## Adapter conformance

The reusable `tests/storage_conformance.py` suite covers rollback, atomic code consumption, concurrent refresh/replay, inactivity/liveness, subject invalidation and credential-digest secrecy. `MemoryStorage` runs it in `tests/test_storage.py`. Against a checkout, place this adapter test under `tests/` (or add that directory to your test import path):

```python
from storage_conformance import StorageConformance
from your_adapter import DurableStorage


class TestDurableStorage(StorageConformance):
    storage_factory = staticmethod(lambda: DurableStorage(fresh_test_database()))
```

Supply your own isolated test-database factory and reset/dispose fixtures; every factory call must return fresh empty storage. Run `python -m pytest tests/test_your_adapter.py`. This is a source-distributed test harness, not a runtime package API. It checks observable behavior within one process; add real multi-process/worker contention, crash recovery and commit-failure tests for your backend. Passing it does not prove deployment durability.
