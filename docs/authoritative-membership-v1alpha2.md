# Authoritative membership v1alpha2

This opt-in extension starts from supported fork commit
`c9a373beca1d602d02308c687db5535c63f3921f`, not an arbitrary upstream release.
The source is https://github.com/kubedoio/buzz; `buzz-elembra` is the image name.

`POST /api/v1/relay/membership/check` accepts canonical `request_id` and
`community_id` UUID strings and a lowercase public key. It uses the existing
trusted-service NIP-98 authentication, mandatory payload hash, Redis replay
guard, host binding and relay-signed kind-19030 envelope. Its content echoes
all request fields and contains `membership`, `membership_revision`,
`send_enabled`, `staged_operation_id` and `evaluated_at`. Bad bodies return 400, foreign/unconfigured communities 404,
and unauthenticated/untrusted callers 401. Unavailable or inconsistent
membership returns 503; communities that have not opted in return 404
(host-resolution failure may also return 404). No failure
is an absence result. The query performs no writes and reads only the primary
pool, never the replica router, channel visibility or signed roster snapshots.
Without a configured stable relay private key, this endpoint returns 503 before
authentication, replay consumption or database access. The public development
fallback key must never sign authoritative membership responses.

## State and ordering

`relay_members` remains the sole active-membership authority.
`relay_membership_state` retains revisions, revocation tombstones and the
separate send gate used by staged admission;
`relay_membership_receipts` retains operation outcomes indefinitely.
Operation UUID uniqueness is deployment-wide and the receipt table is explicitly
registered as a global replay registry. Receipt ownership/access remains bound
to the authorized community, actor and exact command. Reusing a known UUID in
another community fails closed; a concurrent collision can abort the transaction
and must be retried with its original ID. This intentionally couples availability
for colliding IDs; the HTTP mutation handler does not disclose the prior revision.
Migration 0029 locks membership writes while seeding all active records at
revision one. Historically removed keys have no recoverable authoritative
history and initially read absent at zero. Do not reconstruct tombstones from
events; Elembra must retain its historical-key prohibition.

Kind 9030/9031 commands carry one `elembra-op` UUID and one
`elembra-expected-revision` unsigned decimal tag. The database transaction
locks the community (including actor-role authorization), creates/locks the
target revision row, checks the receipt and expected revision, and commits
the membership effect, revision and receipt together. Community serialization
is deliberately conservative. Different operation IDs racing at the same
revision cannot both change state. Conditional transactions require READ
COMMITTED; older repeatable snapshots are rejected before authorization.
PostgreSQL deadlock/transaction failures roll back the entire operation and
must be retried using the same operation
ID after reading current state. Bigint overflow fails closed, never wraps.

The trusted Elembra bridge may add `elembra-stage=true` to a kind-9030
admission. Migration 0030 records its operation UUID and leaves the member
active for signed membership read-back while `send_enabled=false`; EVENT, REQ
and COUNT admission and live subscription fan-out deny that key. Only the
configured trusted-service identity may stage or release membership. After
Elembra commits local activation, its durable outbox sends another kind-9030
command with a fresh `elembra-op`, the expected membership revision and
`elembra-release-of=<staged operation UUID>`. Buzz releases only that exact
still-active staged row and stores the release receipt in the deployment-wide
operation registry. Relay OK acknowledges delivery only; the signed read-back
proves the gate state. Ordinary kind-9030 admissions remain immediately
sendable.

Identical operations return their stored outcome, even after later changes;
this is a receipt, not current-membership proof. Conflicting operation-ID reuse
(including a different actor or role) fails. Stale revisions get durable
rejection receipts; a fresh retry uses a new operation ID. Adding an active
key and removing a revoked key are successful no-ops without revision changes.
Removing an absent key creates revision-one revocation. Revoked keys cannot
be re-added even with the current revision. Receipt replay publishes no
duplicate announcements. Announcement/roster failures cannot roll back or
change membership; the existing startup roster reconciler repairs snapshots.

## Compatibility and rollout

All communities default to v1alpha1. The trigger tracks revisions for legacy
mutations but leaves their add/remove and re-admission behavior intact.
Before opting in a community: stop and drain/quarantine all legacy workers,
upgrade every bridge writer, and obtain architecture/security approval.
In a reviewed maintenance transaction, lock `relay_members` in SHARE ROW
EXCLUSIVE mode and set that community's `membership_v1alpha2=true`.
This is an operator database migration step, not an Elembra database API.
No production community is enabled by this patch.
Opt-in also requires exact-key ACTIVE and send-enabled membership for
authenticated access,
independent of the open-relay setting or NIP-OA owner delegation. An ABSENT or
REVOKED key cannot authenticate, submit events or use a cached WebSocket session;
live subscription fan-out rechecks the primary authority on every delivery.
Anonymous WebSocket requests are denied for opted-in communities. Provision
every service/agent key explicitly before opt-in; delegated agents must also
have their own ACTIVE membership. Legacy communities retain their open/delegated
admission behavior.
Huddle audio revalidates membership before forwarding incoming media and before
sending outgoing audio/control frames, including cross-pod sessions. Denial or
database unavailability cancels the connection. This conservative enforcement
adds primary reads per distinct live event recipient and per audio frame; media
throughput and high-fanout qualification must measure this cost before release.
No cache may turn a revoked key into an admitted key.

For enabled communities the database guard rejects every unversioned
membership/role change, including invites, ownership transfer, operator
insertion and changes to the configured owner. These workflows are unavailable
until they have an explicitly reviewed conditional equivalent. Restart with
the same owner remains supported. Existing v1alpha1 communities retain these
workflows. Do not change the configured owner during a v1alpha2 rollout.

Rollback is application rollback with tables, receipts, tombstones and guard
retained. An old binary cannot safely write an enabled community. Do not
disable v1alpha2 or drop the guard/tables to make old writers work: that would
permit re-admission and erase replay protection. Back up the database before
migration. No automatic destructive down migration is supplied.

## Validation and release gates

The database test upgrades schema 28 with pre-existing memberships, exercises
receipt conflicts, staged admission/release, stale replay, concurrency, legacy compatibility and
connection reopening. The live test launches the actual compiled relay,
uses migrated PostgreSQL and Redis, verifies NIP-98 and relay signatures,
restarts the relay, and pauses only the named disposable test database to
prove failure is closed. Neither test skips when infrastructure is missing.

Run the dedicated `Authoritative membership v1alpha2` workflow and existing
CI. Require independent architecture/security review and human approval.
Only after live conformance and existing Elembra acceptance pass should a
reviewed release build a new immutable image, record its provenance and
digest, and update Elembra's compatibility manifest in a separate PR.
Do not deploy, change the production pin, enable replacement, or expose
pairing UX as part of these PRs.
