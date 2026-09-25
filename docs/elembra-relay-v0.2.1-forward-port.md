# Elembra relay-v0.2.1 forward-port analysis

This document records the capability classification made before implementation
of the Elembra compatibility delta.

## Bases

| Item | Revision |
| --- | --- |
| Upstream repository | `https://github.com/block/buzz.git` |
| Upstream release | `relay-v0.2.1` |
| Upstream release SHA | `6e5c462ac524de60d7edb46c66130fd779cc9006` |
| Previous Elembra fork | `8ce4dac926cdf3bffef1075ffdf49884d1ea3bc4` |
| Previous fork upstream basis | `f53bbd1152464ecbb1de495e2d1d959e156138f0` |

## Capability classification

| Capability | Class | Evidence and forward-port decision |
| --- | --- | --- |
| NIP-98 method, URL, and payload verification | A | relay-v0.2.1 `api::bridge` already verifies the signed request and body binding. Reuse it. |
| NIP-98 freshness and signature validation | A | The upstream `buzz-auth` verifier remains the cryptographic boundary. |
| Shared replay protection | A | relay-v0.2.1 provides the Redis-backed `Nip98ReplayGuard` and tenant-scoped replay check. |
| Multi-community host binding | A | `TenantContext` and `bind_community` are upstream-native. |
| Relay signing keypair | A | `AppState::relay_keypair` and existing signed relay events are upstream-native. |
| Trusted service workload allowlist | B | Upstream has operator allowlisting but no Elembra service-workload allowlist. Add one narrow config gate around the adapter routes. |
| Single access check | C | No equivalent public v1alpha1 endpoint exists. Add the bounded adapter using upstream DB primitives. |
| Batch access check | C | No equivalent public v1alpha1 endpoint exists. Add it through the same decision function as the single check. |
| Authoritative channel registry | B | Upstream exposes channel and accessibility queries. Add only the signed v1alpha1 transport envelope. |
| State/event pagination and tombstones | C | The old fork's bounded channel-scoped state projection is absent from relay-v0.2.1. Restore the minimal query/page model using current event storage. |
| Signed kind-19030 responses | B | Upstream has stable relay signing, but not this Elembra response kind. Add the response envelope and kind constant. |
| Signed community discovery | C | Upstream community provisioning/listing is operator-oriented and does not provide the Elembra bootstrap envelope. Add the host-bound signed discovery route. |
| Admission/revocation | A | NIP-43 membership and durable channel membership handling are upstream-native. The Elembra bridge remains an external client of that public protocol. |
| Channel/message kinds and thread metadata | A | relay-v0.2.1 retains kinds 9/40002 and current thread metadata storage. The adapter reads those public projections only. |
| Docker build and release provenance | B | Upstream release CI/builds the relay; retain only the fork image/publishing and Elembra compatibility checks needed for the supported image. |
| Old fork-only DB helpers | D | Do not replay obsolete helpers blindly. Re-add only the state projection methods required by the v1alpha1 endpoint and adapt them to current storage. |

The adapter will not read Elembra data, add an Elembra ACL, or alter the
upstream authority model. All negative decisions remain fail closed.

## Final maintained delta

The maintained fork delta is limited to:

1. the trusted service-workload allowlist;
2. the v1alpha1 single and batch access endpoints;
3. the signed authoritative channel registry;
4. the signed channel-scoped state/event page with tombstones;
5. signed community identity discovery;
6. the Elembra response kind (`19030`), configuration, tests, and fork image
   publishing/provenance wiring.

The release already supplies NIP-98 verification, replay protection, relay
signing, tenant binding, membership/admission, channel/message semantics, and
thread metadata, so those implementations were reused rather than forked.

## Validation evidence

- `cargo check -p buzz-relay`: PASS.
- `cargo clippy -p buzz-relay --all-targets --all-features -- -D warnings`:
  PASS.
- The ignored `api::relay_access::tests` suite: **48 passed, 0 failed** against
  Postgres and Redis.
- The full `buzz-relay` library suite: **869 passed, 1 failed, 88 ignored**.
  The single failure is the upstream `api::mesh_demo::tests::demo_join_forwarded_arm_round_trips_echo`
  504/200 assertion; it reproduces unchanged on pristine `relay-v0.2.1` and is
  outside the Elembra delta.
- A copy of an old-image database at migration 28, containing two channels,
  memberships including one revoked member, sixteen events, and one tombstone,
  started with the candidate and `BUZZ_AUTO_MIGRATE=true`. The community ID,
  channel IDs, event count, tombstone, revoked membership, and migration level
  were unchanged. Dedicated RustFS was copied to a separate bucket and the
  candidate's object-store startup probe passed.
- The old supported image restarted successfully against that candidate-updated
  copy. Rollback classification is therefore **A** for the current migration-28
  schema; any future schema-changing release must repeat this proof and may
  require a database/storage snapshot restore.

The RustShare supported deployment remains the owner of the pinned dedicated
Buzz RustFS Compose configuration. The upstream development Compose file is
not the Elembra compatibility path.

## Candidate artifact

The reviewed fork head is `853cc331a80b4fb6551ad895f2d9039d8f903758` and the
immutable candidate is
`ghcr.io/kubedoio/buzz@sha256:ed82b0a0f0351bb33018e50b7d472fe8d92f6a50e8dfb8e8ebd2f8a04b763742`
(tag `0.2.1-elembra.4`). Native image release workflow `36164497937` passed
for the published architectures and emitted provenance. Root and harness
Compose use the same pinned RustFS runtime/client images; no MinIO image is
required by the supported relay test/development path.
