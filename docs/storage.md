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
- Capacity check and insert occur under the same transaction. Prune expired codes, consents and families. Client expiry/deletion cascades to its codes, pending state and grants. Missing/deleted clients cannot leave valid access credentials.
- Persist only digests for codes/access/refresh/consent tickets. Pending state contains public authorization input, state and challenge, never verifier or bearer credentials. Protect storage/backups as private data.
- Constant-time direct digest comparisons; digest-indexed database lookup is appropriate for high-entropy credentials. Index client IDs and all current/used digests with uniqueness constraints.
- Coordinate authoritative identity version/incarnation checks with account writes. Stable ID alone does not protect delete/recreate or reset races.

## Records and operations

Client: exact redirects, scopes/grants, name, ID/time. Code: digest, subject/version, client/redirect/resource/scope/challenge/expiry. PendingConsent: ticket digest, subject/version, original authorization parameters/expiry. Grant: family ID, subject/version, client/resource/narrowed scope, original/absolute/access times, current access/refresh digests, used-refresh tuple, revoked flag.

UnitOfWork exposes explicit get/put/delete/list methods, token-digest lookup and pruning; the contract does not depend on a host database schema. Immutable records support atomic replacement. List methods materialize bounded state in v0.1; production should use indexed access inside these operations. Capacity and rotation limits bound replay growth.

## MemoryStorage limitation

**Development/single-process only.** One RLock serializes transactions. Each uses a private deep copy, installed only on successful exit. Scans/copies grow with state; production needs an indexed durable adapter. Separate workers do not share memory.

snapshot/from_snapshot are trusted fixture export/reload, not an import API or durable database. Never load untrusted snapshots. Tests verify digest secrecy, reload, pruning, concurrent code/refresh operations and commit failures for registration/consent/code issuance/exchange/refresh.

Do not perform unbounded network work in a storage lock. Identity's authoritative lookup is synchronous. Render/decision callbacks are outside transactions; completion revalidates the pending consent and current subject before issuing a code. Host login/identity can share the same durable account transaction strategy for stronger account-write coordination.
