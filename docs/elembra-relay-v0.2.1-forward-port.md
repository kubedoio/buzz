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
