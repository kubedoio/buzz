//! Relay authorization API — `POST /api/v1/relay/access/check`,
//! `POST /api/v1/relay/access/check-batch`, and
//! `GET /api/v1/relay/channels` (the authoritative channel registry).
//!
//! Lets a provisioned trusted service workload (which never holds a human
//! user's signing key) ask the relay whether a given pubkey may currently read
//! a given channel/message, or enumerate the channels that pubkey may read.
//! The answers derive exclusively from the relay's own state (channel
//! visibility, membership, message availability); the request's `channel_kind`
//! is never trusted.
//!
//! Authentication is NIP-98 (kind-27235) and the caller must be in the
//! deployment's `relay_trusted_service_pubkeys` allowlist (empty allowlist =
//! the API is disabled, every caller gets 401). Responses are raw signed
//! kind-19030 Nostr events, signed by the relay's keypair, whose `content`
//! echoes the request `pubkey`/`channel_id`/`message_id` verbatim so the
//! client can bind the decision to the exact check it asked for.
//!
//! Existence hiding: no membership lists are ever returned and `reason`
//! strings never reveal whether other users exist (`"not a member"`).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::{
    extract::{Query, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

use buzz_core::kind::KIND_RELAY_AUTHZ_RESPONSE;
use buzz_core::StoredEvent;
use buzz_db::channel::ChannelRecord;
use buzz_db::DbError;

use crate::state::AppState;

use super::bridge::{
    check_nip98_replay, enforce_http_admission, nip98_expected_url, verify_bridge_auth,
};
use super::{api_error, internal_error};

/// The endpoint path — the NIP-98 `u` tag must match the exact request URL.
const ACCESS_CHECK_PATH: &str = "/api/v1/relay/access/check";
/// The batch endpoint path — the NIP-98 `u` tag must match the exact request URL.
const ACCESS_CHECK_BATCH_PATH: &str = "/api/v1/relay/access/check-batch";
/// The channel-registry endpoint path — the NIP-98 `u` tag must match the
/// exact request URL including the query string.
const RELAY_CHANNELS_PATH: &str = "/api/v1/relay/channels";
/// The state-events endpoint path — the NIP-98 `u` tag must match the exact
/// request URL including the query string.
const RELAY_STATE_EVENTS_PATH: &str = "/api/v1/relay/state/events";
/// Maximum number of checks per batch request (contract: at most 64).
const MAX_BATCH_CHECKS: usize = 64;
/// Page-size clamp for the state-events endpoint (contract: 1..=500).
const STATE_EVENTS_MAX_LIMIT: i64 = 500;
/// Default page size for the state-events endpoint when `limit` is absent.
const STATE_EVENTS_DEFAULT_LIMIT: i64 = 500;

/// A single access-check request body.
///
/// `channel_kind` and `event_created_at` are informational: the relay decides
/// from its own state and ignores both (the fields exist so the client can
/// send them without any validation change).
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // channel_kind/event_created_at are contract-mandated and intentionally unused
struct AccessCheckRequest {
    /// 64-hex pubkey of the principal being checked.
    pubkey: String,
    /// Channel UUID string.
    channel_id: String,
    /// Client-projected channel kind (`workspace|dm|private|excluded`).
    /// Never trusted for the decision.
    channel_kind: String,
    /// Optional 64-hex event ID; `null`/absent means a channel-level check.
    message_id: Option<String>,
    /// Optional unix-seconds creation time of the event being checked.
    event_created_at: Option<i64>,
}

/// A batch access-check request body.
#[derive(Debug, Deserialize)]
struct AccessCheckBatchRequest {
    /// The checks to evaluate, in order; at most [`MAX_BATCH_CHECKS`].
    checks: Vec<AccessCheckRequest>,
}

/// A validated access-check item with typed fields, ready for evaluation.
struct ParsedCheck {
    /// Channel UUID from the request.
    channel_id: uuid::Uuid,
    /// 32-byte subject pubkey.
    subject_bytes: Vec<u8>,
    /// Optional 32-byte message id; `None` = channel-level check.
    message_id_bytes: Option<[u8; 32]>,
}

/// Parse and validate a single-check request body into typed fields.
///
/// Malformed fields (non-hex pubkey, non-UUID channel id, malformed message
/// id) fail the whole request with 400 — shared by both endpoints.
fn parse_check(req: &AccessCheckRequest) -> Result<ParsedCheck, (StatusCode, Json<Value>)> {
    let subject_pubkey = nostr::PublicKey::from_hex(&req.pubkey)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid pubkey"))?;
    let channel_id: uuid::Uuid = req
        .channel_id
        .parse()
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid channel_id"))?;
    let message_id_bytes: Option<[u8; 32]> = match req.message_id.as_deref() {
        Some(hex_str) => {
            let decoded = hex::decode(hex_str)
                .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid message_id"))?;
            Some(
                <[u8; 32]>::try_from(decoded.as_slice())
                    .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid message_id"))?,
            )
        }
        None => None,
    };
    Ok(ParsedCheck {
        channel_id,
        subject_bytes: subject_pubkey.to_bytes().to_vec(),
        message_id_bytes,
    })
}

/// Evaluate one access check from relay state already resolved by the caller.
///
/// Shared by the single and batch endpoints so their semantics cannot drift.
/// `channel` is `None` when the channel does not exist (or is soft-deleted);
/// `is_member` is the pre-resolved active-membership answer; `message` is the
/// pre-resolved non-deleted event, only meaningful when `parsed` carries a
/// message id. All lookups are community-scoped by the caller.
fn decide(
    channel: Option<&ChannelRecord>,
    is_member: bool,
    message: Option<&StoredEvent>,
    parsed: &ParsedCheck,
) -> (Decision, &'static str) {
    let Some(channel) = channel else {
        return (Decision::NotFound, "not found");
    };
    // Readability: an active member, or an open channel anyone may read.
    if !is_member && channel.visibility != "open" {
        // Existence hiding: never reveal who is or is not a member.
        return (Decision::Deny, "not a member");
    }
    match parsed.message_id_bytes {
        // Message-level availability: the message must exist, be non-deleted,
        // and belong to the checked channel; anything else is `not_found`
        // (never reveals the message exists elsewhere).
        Some(_) => match message {
            Some(se) if se.channel_id == Some(parsed.channel_id) => (Decision::Allow, "allowed"),
            _ => (Decision::NotFound, "not found"),
        },
        // Channel-level check: readable is enough.
        None => (Decision::Allow, "allowed"),
    }
}

/// The decision outcome, serialized snake_case into the response `content`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum Decision {
    /// The pubkey may currently read the channel/message.
    Allow,
    /// The pubkey is not admitted to the channel.
    Deny,
    /// The channel or message does not exist (or is deleted) — indistinguishable
    /// from the caller's perspective, preserving existence hiding.
    NotFound,
}

/// Ask whether a pubkey may currently read a channel/message.
///
/// NIP-98 authenticated (mandatory — no dev-mode X-Pubkey fallback, so the
/// trusted-service gate below always reflects cryptographic identity) and
/// gated on `relay_trusted_service_pubkeys`. Returns a relay-signed kind-19030
/// event; HTTP 401 for auth/trust failures, 400 for malformed bodies, and no
/// 5xx for a negative decision.
pub async fn check_access(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Row zero: the community is derived from the request Host, never from
    // client-supplied ids in the body. Unmapped host or lookup failure fails
    // closed with a generic rejection.
    let raw_host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let tenant = crate::tenant::bind_community(&state.db, raw_host)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::NOT_FOUND,
                "relay: no community is configured for this host",
            )
        })?;

    // NIP-98 (kind-27235): `u` tag = exact request URL for this host, `method`
    // tag = POST, `payload` tag = hex SHA-256 of the body. `require_auth_token`
    // is pinned true so the bridge's dev-mode X-Pubkey fallback can never
    // impersonate a trusted service key without a signature.
    let url = nip98_expected_url(&state.config.relay_url, &tenant, ACCESS_CHECK_PATH);
    let (caller_pubkey, event_id_bytes) =
        verify_bridge_auth(&headers, "POST", &url, Some(&body), true)?;

    // Trusted-service gate: only provisioned service pubkeys may call the
    // authorization API. An empty allowlist disables it entirely (fail closed).
    let caller_hex = caller_pubkey.to_hex();
    if !state
        .config
        .relay_trusted_service_pubkeys
        .iter()
        .any(|trusted| trusted == &caller_hex)
    {
        return Err(api_error(StatusCode::UNAUTHORIZED, "untrusted caller"));
    }

    // Admission (rate limit) and NIP-98 replay protection — the same gates as
    // the HTTP bridge endpoints.
    enforce_http_admission(&state, &tenant, &caller_pubkey).await?;
    check_nip98_replay(&state, &tenant, event_id_bytes).await?;

    let req: AccessCheckRequest = serde_json::from_slice(&body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "malformed request body"))?;
    let parsed = parse_check(&req)?;

    let evaluated_at = nostr::Timestamp::now().as_secs() as i64;

    // Channel lookup from the relay's own state; unknown or soft-deleted
    // channels are indistinguishable (`ChannelNotFound`).
    let channel = match state
        .db
        .get_channel(tenant.community(), parsed.channel_id)
        .await
    {
        Ok(ch) => Some(ch),
        Err(DbError::ChannelNotFound(_)) => None,
        Err(e) => return Err(internal_error(&format!("channel lookup failed: {e}"))),
    };

    // Readability: an active member, or an open channel anyone may read.
    let is_member = state
        .db
        .is_member(tenant.community(), parsed.channel_id, &parsed.subject_bytes)
        .await
        .map_err(|e| internal_error(&format!("membership check failed: {e}")))?;

    // Message-level availability, when a message id was given.
    let message = match parsed.message_id_bytes {
        Some(id_bytes) => state
            .db
            .get_event_by_id(tenant.community(), &id_bytes)
            .await
            .map_err(|e| internal_error(&format!("event lookup failed: {e}")))?,
        None => None,
    };

    let (decision, reason) = decide(channel.as_ref(), is_member, message.as_ref(), &parsed);
    decision_response(&state, evaluated_at, decision, reason, &req)
}

/// Sign a kind-19030 authorization response event with `content` as its
/// `content` field, using the relay's keypair.
fn sign_response(
    state: &AppState,
    content: Value,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let event = nostr::EventBuilder::new(
        nostr::Kind::Custom(KIND_RELAY_AUTHZ_RESPONSE as u16),
        content.to_string(),
    )
    .sign_with_keys(&state.relay_keypair)
    .map_err(|e| internal_error(&format!("failed to sign authorization response: {e}")))?;
    serde_json::to_value(&event)
        .map(Json)
        .map_err(|e| internal_error(&format!("failed to serialize authorization response: {e}")))
}

/// Build the signed kind-19030 response event for a decision.
///
/// The `content` echoes the request `pubkey`, `channel_id`, and `message_id`
/// verbatim (`message_id: null` when the request had none) so the client can
/// bind the decision to the exact check that was asked for.
fn decision_response(
    state: &AppState,
    evaluated_at: i64,
    decision: Decision,
    reason: &str,
    req: &AccessCheckRequest,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let content = serde_json::json!({
        "decision": decision,
        "reason": reason,
        "evaluated_at": evaluated_at,
        "pubkey": &req.pubkey,
        "channel_id": &req.channel_id,
        "message_id": &req.message_id,
    });
    sign_response(state, content)
}

/// Ask whether a pubkey may currently read multiple channels/messages in one
/// round-trip.
///
/// The request carries at most [`MAX_BATCH_CHECKS`] checks (more → 400); an
/// empty `checks` list is valid and yields an empty `results` array. Each item
/// is evaluated with the exact single-check semantics, order-preserving
/// (`results[i]` ↔ `checks[i]`), with verbatim per-item echo of
/// `pubkey`/`channel_id`/`message_id`. A relay-side evaluation error for one
/// item (e.g. a channel lookup failure) yields `deny` for that item only with
/// a generic reason — the remaining items are still evaluated. Request-level
/// problems (malformed JSON, malformed item fields, more than
/// [`MAX_BATCH_CHECKS`] items) fail the whole request with 400.
///
/// The response is a single kind-19030 event signed by the relay key; its
/// top-level `evaluated_at` is the freshness authority for the whole batch and
/// each item's `evaluated_at` mirrors it.
///
/// Auth pipeline identical to [`check_access`]: host-derived community, NIP-98
/// pinned mandatory, trusted-service gate, admission, replay.
pub async fn check_access_batch(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Row zero: the community is derived from the request Host, never from
    // client-supplied ids in the body.
    let raw_host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let tenant = crate::tenant::bind_community(&state.db, raw_host)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::NOT_FOUND,
                "relay: no community is configured for this host",
            )
        })?;

    // NIP-98 (kind-27235), pinned mandatory — no dev-mode X-Pubkey fallback.
    let url = nip98_expected_url(&state.config.relay_url, &tenant, ACCESS_CHECK_BATCH_PATH);
    let (caller_pubkey, event_id_bytes) =
        verify_bridge_auth(&headers, "POST", &url, Some(&body), true)?;

    // Trusted-service gate: only provisioned service pubkeys may call the
    // authorization API. An empty allowlist disables it entirely (fail closed).
    let caller_hex = caller_pubkey.to_hex();
    if !state
        .config
        .relay_trusted_service_pubkeys
        .iter()
        .any(|trusted| trusted == &caller_hex)
    {
        return Err(api_error(StatusCode::UNAUTHORIZED, "untrusted caller"));
    }

    // Admission (rate limit) and NIP-98 replay protection.
    enforce_http_admission(&state, &tenant, &caller_pubkey).await?;
    check_nip98_replay(&state, &tenant, event_id_bytes).await?;

    let batch: AccessCheckBatchRequest = serde_json::from_slice(&body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "malformed request body"))?;

    // Cap enforcement before any DB work.
    if batch.checks.len() > MAX_BATCH_CHECKS {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            &format!("too many checks: max {MAX_BATCH_CHECKS}"),
        ));
    }

    // Parse every item up front — a malformed item fails the whole request.
    let mut parsed: Vec<ParsedCheck> = Vec::with_capacity(batch.checks.len());
    let mut message_ids: Vec<[u8; 32]> = Vec::new();
    for req in &batch.checks {
        let item = parse_check(req)?;
        if let Some(id) = item.message_id_bytes {
            message_ids.push(id);
        }
        parsed.push(item);
    }

    let evaluated_at = nostr::Timestamp::now().as_secs() as i64;

    // One membership query for every item — same per-pair semantics as the
    // single check's `is_member` (active membership on a non-deleted channel).
    let channel_ids: Vec<uuid::Uuid> = parsed.iter().map(|p| p.channel_id).collect();
    let pubkeys: Vec<Vec<u8>> = parsed.iter().map(|p| p.subject_bytes.clone()).collect();
    let membership_pairs = state
        .db
        .membership_pairs(tenant.community(), &channel_ids, &pubkeys)
        .await
        .map_err(|e| internal_error(&format!("membership batch lookup failed: {e}")))?;
    let members: HashSet<(uuid::Uuid, Vec<u8>)> = membership_pairs.into_iter().collect();

    // One message-availability query for every checked message id — non-deleted
    // only, community-scoped.
    let id_refs: Vec<&[u8]> = message_ids.iter().map(|m| m.as_slice()).collect();
    let stored_events = state
        .db
        .get_events_by_ids(tenant.community(), &id_refs)
        .await
        .map_err(|e| internal_error(&format!("event batch lookup failed: {e}")))?;
    let events_by_id: HashMap<[u8; 32], StoredEvent> = stored_events
        .into_iter()
        .map(|se| (se.event.id.to_bytes(), se))
        .collect();

    // Evaluate each item. Channel existence/visibility is resolved per item
    // (no bulk channel fetch exists); membership and message availability are
    // already resolved for the whole batch. A per-item channel lookup failure
    // is isolated to that item (deny, generic reason).
    let mut results: Vec<(Decision, &'static str, &AccessCheckRequest)> =
        Vec::with_capacity(batch.checks.len());
    for (i, (req, item)) in batch.checks.iter().zip(parsed.iter()).enumerate() {
        let channel = match state
            .db
            .get_channel(tenant.community(), item.channel_id)
            .await
        {
            Ok(ch) => Some(ch),
            Err(DbError::ChannelNotFound(_)) => None,
            Err(e) => {
                tracing::warn!(
                    item = i,
                    error = %e,
                    "batch access check: channel lookup failed for item; denying item"
                );
                results.push((Decision::Deny, "evaluation error", req));
                continue;
            }
        };
        let is_member = members.contains(&(item.channel_id, item.subject_bytes.clone()));
        let message = item
            .message_id_bytes
            .as_ref()
            .and_then(|id| events_by_id.get(id));
        let (decision, reason) = decide(channel.as_ref(), is_member, message, item);
        results.push((decision, reason, req));
    }

    batch_response(&state, evaluated_at, &results)
}

/// Build the signed kind-19030 response event for a batch of decisions.
///
/// One event for the whole batch; `results` is order-preserving
/// (`results[i]` ↔ `checks[i]`), each item echoes its request's
/// `pubkey`/`channel_id`/`message_id` verbatim, and the top-level
/// `evaluated_at` is the freshness authority (each item's `evaluated_at`
/// mirrors it).
fn batch_response(
    state: &AppState,
    evaluated_at: i64,
    results: &[(Decision, &'static str, &AccessCheckRequest)],
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let results_json: Vec<Value> = results
        .iter()
        .map(|(decision, reason, req)| {
            serde_json::json!({
                "decision": decision,
                "reason": reason,
                "evaluated_at": evaluated_at,
                "pubkey": &req.pubkey,
                "channel_id": &req.channel_id,
                "message_id": &req.message_id,
            })
        })
        .collect();
    let content = serde_json::json!({
        "results": results_json,
        "evaluated_at": evaluated_at,
    });
    sign_response(state, content)
}

/// Query for `GET /api/v1/relay/channels`.
#[derive(serde::Deserialize)]
pub struct ChannelsQuery {
    /// 64-hex pubkey to list channels for.
    pubkey: String,
}

/// List the channels a given pubkey may currently read — the authoritative
/// channel registry.
///
/// NIP-98 GET: the `u` tag covers the exact request URL INCLUDING the query
/// string, so the `pubkey` parameter is bound by the signature (GET carries
/// no `payload` tag). Returns one kind-19030 event signed by the relay key
/// whose `content` lists only channels the pubkey may read — member channels
/// (including private ones) plus open channels, each with a `member` flag
/// stating active membership — and echoes the query `pubkey` verbatim.
/// Host-derived community only; untrusted callers get 401 (same
/// trusted-service gate as the check endpoints). Existence hiding: channels
/// the pubkey may not read are never included, and neither are another
/// community's channels.
pub async fn list_channels(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    Query(query): Query<ChannelsQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Row zero: the community is derived from the request Host, never from
    // client-supplied ids.
    let raw_host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let tenant = crate::tenant::bind_community(&state.db, raw_host)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::NOT_FOUND,
                "relay: no community is configured for this host",
            )
        })?;

    // NIP-98 (kind-27235), pinned mandatory — no dev-mode X-Pubkey fallback.
    // The `u` tag covers path + raw query string (same construction as the
    // moderation GETs in `bridge.rs`), so the signed `pubkey` cannot be
    // swapped after the fact.
    let path_with_query = match raw_query {
        Some(q) if !q.is_empty() => format!("{RELAY_CHANNELS_PATH}?{q}"),
        _ => RELAY_CHANNELS_PATH.to_string(),
    };
    let url = nip98_expected_url(&state.config.relay_url, &tenant, &path_with_query);
    let (caller_pubkey, event_id_bytes) = verify_bridge_auth(&headers, "GET", &url, None, true)?;

    // Trusted-service gate: only provisioned service pubkeys may call the
    // authorization API. An empty allowlist disables it entirely (fail closed).
    let caller_hex = caller_pubkey.to_hex();
    if !state
        .config
        .relay_trusted_service_pubkeys
        .iter()
        .any(|trusted| trusted == &caller_hex)
    {
        return Err(api_error(StatusCode::UNAUTHORIZED, "untrusted caller"));
    }

    // Admission (rate limit) and NIP-98 replay protection.
    enforce_http_admission(&state, &tenant, &caller_pubkey).await?;
    check_nip98_replay(&state, &tenant, event_id_bytes).await?;

    let subject = nostr::PublicKey::from_hex(&query.pubkey)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid pubkey"))?;
    let evaluated_at = nostr::Timestamp::now().as_secs() as i64;

    // One query: member ∪ open channels of this community (non-deleted), with
    // the per-channel `is_member` flag computed in the same statement. DM
    // channels the pubkey has hidden (`channel_members.hidden_at` set) are
    // excluded by the query itself; other users' DM channels are never
    // readable, so they never appear.
    let accessible = state
        .db
        .get_accessible_channels(tenant.community(), &subject.to_bytes(), None, None)
        .await
        .map_err(|e| internal_error(&format!("accessible channels lookup failed: {e}")))?;

    let channels_json: Vec<Value> = accessible
        .iter()
        .map(|ac| {
            serde_json::json!({
                "channel_id": ac.channel.id.to_string(),
                "name": &ac.channel.name,
                "channel_type": &ac.channel.channel_type,
                "visibility": &ac.channel.visibility,
                "member": ac.is_member,
            })
        })
        .collect();

    let content = serde_json::json!({
        "channels": channels_json,
        "evaluated_at": evaluated_at,
        "pubkey": &query.pubkey,
    });
    sign_response(&state, content)
}

/// Query for `GET /api/v1/relay/state/events`.
#[derive(serde::Deserialize)]
pub struct StateEventsQuery {
    /// Only events whose own `created_at` is at or after this unix timestamp.
    since: Option<i64>,
    /// Maximum page size, clamped to 1..=[`STATE_EVENTS_MAX_LIMIT`].
    limit: Option<i64>,
    /// Opaque continuation token from a previous page (base64 of
    /// `<created_at_unix>:<event_id_hex>`).
    cursor: Option<String>,
}

/// A parsed state-events keyset cursor position.
struct StateCursor {
    /// The `created_at` of the previous page's last row.
    created_at: DateTime<Utc>,
    /// The event id of the previous page's last row.
    id: Vec<u8>,
}

/// Encode the opaque state-events cursor for the last row of a page.
///
/// Format: base64 of `"<created_at_unix>:<event_id_hex>"` — documented here
/// as the wire contract for the endpoint.
fn encode_state_cursor(created_at: DateTime<Utc>, id: &[u8]) -> String {
    let text = format!("{}:{}", created_at.timestamp(), hex::encode(id));
    BASE64.encode(text)
}

/// Parse an opaque state-events cursor back into its keyset position.
///
/// Malformed cursors (bad base64, missing separator, non-numeric timestamp,
/// non-hex id) fail closed with 400 — never silently restart the paging.
fn parse_state_cursor(raw: &str) -> Result<StateCursor, (StatusCode, Json<Value>)> {
    let decoded = BASE64
        .decode(raw)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid cursor"))?;
    let text = String::from_utf8(decoded)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid cursor"))?;
    let (ts_part, id_part) = text
        .split_once(':')
        .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "invalid cursor"))?;
    let ts: i64 = ts_part
        .parse()
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid cursor"))?;
    let created_at = DateTime::from_timestamp(ts, 0)
        .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "invalid cursor"))?;
    let id =
        hex::decode(id_part).map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid cursor"))?;
    Ok(StateCursor { created_at, id })
}

/// Map a Buzz channel to the Elembra channel-kind vocabulary.
///
/// `dm` channels → `"dm"`; anything else that is private → `"private"`;
/// everything else → `"workspace"`. `"excluded"` is an Elembra-side concept
/// and is never emitted.
fn map_channel_kind(channel_type: &str, visibility: &str) -> &'static str {
    if channel_type == "dm" {
        "dm"
    } else if visibility == "private" {
        "private"
    } else {
        "workspace"
    }
}

/// Page the community's signed kind-1 event state for reconciliation.
///
/// NIP-98 GET: the `u` tag covers the exact request URL INCLUDING the query
/// string (GET carries no `payload` tag), so `since`/`limit`/`cursor` are
/// bound by the signature. Returns one kind-19030 event signed by the relay
/// key whose `content` is `{ "entries": [...], "cursor": <opaque>|null,
/// "complete": bool }`.
///
/// Each entry carries the raw signed kind-1 event JSON plus a `context`
/// field-for-field identical to Elembra's `BuzzPushContext`:
/// `{ community_id, channel_id, channel_kind, thread_root_id|null,
/// message_id, event_type, supersedes_event_id|null }`. `channel_kind` is
/// mapped from the relay's own channel state (dm → `"dm"`, private →
/// `"private"`, else → `"workspace"`; `"excluded"` is never emitted);
/// `event_type` is `"deleted"` for soft-deleted (tombstoned) events and
/// `"created"` otherwise (`"edited"` is never emitted — kind-1 events are
/// immutable); `supersedes_event_id` is always null in v1alpha1.
///
/// Paging is keyset-ordered by `(created_at ASC, event_id ASC)` over the
/// event's own `created_at`; `since` filters inclusively on it and `limit`
/// is clamped to 1..=500 (out-of-range values clamp, never error). The
/// cursor is opaque base64 of `<created_at_unix>:<event_id_hex>`; the final
/// page reports `complete: true, cursor: null` (never `cursor: null` with
/// `complete: false`). Only the Host-derived community's channel-scoped
/// kind-1 events are paged; events of soft-deleted channels are excluded.
/// Untrusted callers get 401 (same trusted-service gate as the other
/// endpoints).
pub async fn page_state(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    Query(query): Query<StateEventsQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Row zero: the community is derived from the request Host, never from
    // client-supplied ids.
    let raw_host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let tenant = crate::tenant::bind_community(&state.db, raw_host)
        .await
        .map_err(|_| {
            api_error(
                StatusCode::NOT_FOUND,
                "relay: no community is configured for this host",
            )
        })?;

    // NIP-98 (kind-27235), pinned mandatory — no dev-mode X-Pubkey fallback.
    // The `u` tag covers path + raw query string, so the paging parameters
    // cannot be swapped after the fact.
    let path_with_query = match raw_query {
        Some(q) if !q.is_empty() => format!("{RELAY_STATE_EVENTS_PATH}?{q}"),
        _ => RELAY_STATE_EVENTS_PATH.to_string(),
    };
    let url = nip98_expected_url(&state.config.relay_url, &tenant, &path_with_query);
    let (caller_pubkey, event_id_bytes) = verify_bridge_auth(&headers, "GET", &url, None, true)?;

    // Trusted-service gate: only provisioned service pubkeys may call the
    // authorization API. An empty allowlist disables it entirely (fail closed).
    let caller_hex = caller_pubkey.to_hex();
    if !state
        .config
        .relay_trusted_service_pubkeys
        .iter()
        .any(|trusted| trusted == &caller_hex)
    {
        return Err(api_error(StatusCode::UNAUTHORIZED, "untrusted caller"));
    }

    // Admission (rate limit) and NIP-98 replay protection.
    enforce_http_admission(&state, &tenant, &caller_pubkey).await?;
    check_nip98_replay(&state, &tenant, event_id_bytes).await?;

    let since: Option<DateTime<Utc>> = match query.since {
        Some(ts) => Some(
            DateTime::from_timestamp(ts, 0)
                .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "invalid since"))?,
        ),
        None => None,
    };
    let after = match query.cursor.as_deref() {
        Some(raw) => {
            let cursor = parse_state_cursor(raw)?;
            Some((cursor.created_at, cursor.id))
        }
        None => None,
    };
    let limit = query
        .limit
        .unwrap_or(STATE_EVENTS_DEFAULT_LIMIT)
        .clamp(1, STATE_EVENTS_MAX_LIMIT) as usize;

    let page = state
        .db
        .query_state_events(tenant.community(), since, after, limit)
        .await
        .map_err(|e| internal_error(&format!("state events page failed: {e}")))?;

    // One batch query for the thread roots of every event on the page.
    let event_ids: Vec<Vec<u8>> = page
        .rows
        .iter()
        .map(|row| row.stored_event.event.id.to_bytes().to_vec())
        .collect();
    let thread_roots = state
        .db
        .get_thread_roots(tenant.community(), &event_ids)
        .await
        .map_err(|e| internal_error(&format!("thread root lookup failed: {e}")))?;

    let community_id = tenant.community().to_string();
    let entries: Vec<Value> = page
        .rows
        .iter()
        .map(|row| {
            let event = &row.stored_event.event;
            let event_id = event.id.to_bytes().to_vec();
            let thread_root_id = thread_roots.get(&event_id).map(hex::encode);
            serde_json::json!({
                "event": event,
                "context": {
                    "community_id": community_id,
                    "channel_id": row.channel_id.to_string(),
                    "channel_kind": map_channel_kind(&row.channel_type, &row.visibility),
                    "thread_root_id": thread_root_id,
                    "message_id": event.id.to_hex(),
                    "event_type": if row.is_deleted { "deleted" } else { "created" },
                    "supersedes_event_id": None::<String>,
                },
            })
        })
        .collect();

    // Final page: `complete: true, cursor: null`; otherwise the cursor of the
    // last returned row (never `cursor: null` with `complete: false`).
    let cursor = match page.rows.last() {
        Some(last) if page.has_more => {
            let created_at =
                DateTime::from_timestamp(last.stored_event.event.created_at.as_secs() as i64, 0)
                    .ok_or_else(|| internal_error("invalid event created_at"))?;
            Some(encode_state_cursor(
                created_at,
                last.stored_event.event.id.as_bytes(),
            ))
        }
        _ => None,
    };
    let complete = !page.has_more;

    let content = serde_json::json!({
        "entries": entries,
        "cursor": cursor,
        "complete": complete,
    });
    sign_response(&state, content)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::{to_bytes, Body},
        http::{header, Request, StatusCode},
    };
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use buzz_auth::Nip98ReplayGuard;
    use buzz_core::CommunityId;
    use nostr::{EventBuilder, EventId, Keys, Kind, Tag};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;
    use crate::router::build_router;

    /// NIP-98 replay guard that never rejects — the test harness has no Redis.
    struct AlwaysFreshReplayGuard;

    impl Nip98ReplayGuard for AlwaysFreshReplayGuard {
        fn try_mark_in_scope<'a>(
            &'a self,
            _scope: &'a str,
            _event_id: &'a nostr::EventId,
            _ttl_secs: u64,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<bool, buzz_auth::AuthError>> + Send + 'a>,
        > {
            Box::pin(async { Ok(true) })
        }
    }

    const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz"; // sadscan:disable np.postgres.1
    const TEST_REDIS_URL: &str = "redis://127.0.0.1:6379";

    struct TestState {
        state: Arc<AppState>,
        service_keys: Keys,
        relay_pubkey: nostr::PublicKey,
    }

    /// Build an AppState for handler-level tests: fresh community on `host`,
    /// NIP-98 replay stubbed fresh, admission against a live local Redis (the
    /// admission gate fails closed without one — same constraint as the bridge
    /// tests). The caller's key is the trusted service. Returns `None` when
    /// Postgres is unavailable.
    async fn access_check_test_state(host: &str) -> Option<TestState> {
        let service_keys = Keys::generate();
        let allowlist = vec![service_keys.public_key().to_hex()];
        access_check_test_state_with_allowlist(host, service_keys, allowlist).await
    }

    /// Core state builder with an explicit trusted-service allowlist.
    ///
    /// `allowlist` is set verbatim on the config, so `vec![]` exercises the
    /// fail-closed default (empty allowlist = the API is disabled).
    async fn access_check_test_state_with_allowlist(
        host: &str,
        service_keys: Keys,
        allowlist: Vec<String>,
    ) -> Option<TestState> {
        let mut config = crate::config::Config::from_env().ok()?;
        let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| TEST_DB_URL.to_string());
        config.database_url = database_url.clone();
        config.redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| TEST_REDIS_URL.to_string());
        config.relay_url = format!("wss://{host}");
        config.require_auth_token = true;
        config.require_relay_membership = false;
        config.relay_trusted_service_pubkeys = allowlist;

        let pool = sqlx::PgPool::connect(&database_url).await.ok()?;
        let db = buzz_db::Db::from_pool(pool.clone());
        db.migrate().await.ok()?;
        db.ensure_configured_community(host).await.ok()?;

        let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .ok()?;
        let pubsub = Arc::new(
            buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
                .await
                .ok()?,
        );
        let audit = buzz_audit::AuditService::new(pool.clone());
        let auth = buzz_auth::AuthService::new(config.auth.clone());
        let search = buzz_search::SearchService::new(pool.clone());
        let workflow_engine = Arc::new(buzz_workflow::WorkflowEngine::new(
            db.clone(),
            buzz_workflow::WorkflowConfig::default(),
        ));
        let media_storage = buzz_media::MediaStorage::new(&config.media).ok()?;

        let relay_keys = Keys::generate();
        let relay_pubkey = relay_keys.public_key();
        let (mut state, _audit_shutdown) = AppState::new(
            config,
            db,
            redis_pool,
            audit,
            pubsub,
            auth,
            search,
            workflow_engine,
            relay_keys,
            media_storage,
        );
        state.nip98_replay = Arc::new(AlwaysFreshReplayGuard);
        Some(TestState {
            state: Arc::new(state),
            service_keys,
            relay_pubkey,
        })
    }

    struct ChannelFixture {
        community: CommunityId,
        channel_id: Uuid,
        member_keys: Keys,
    }

    /// Seed a community (fresh host), a channel, and one member; the channel
    /// creator is bootstrapped as owner. The member is a fresh random key.
    async fn seed_channel(
        db: &buzz_db::Db,
        host: &str,
        visibility: buzz_db::channel::ChannelVisibility,
    ) -> Option<ChannelFixture> {
        seed_channel_with_member(db, host, visibility, &Keys::generate()).await
    }

    /// [`seed_channel`] with an explicit member key (e.g. the subject under
    /// test) added as the channel's member.
    async fn seed_channel_with_member(
        db: &buzz_db::Db,
        host: &str,
        visibility: buzz_db::channel::ChannelVisibility,
        member: &Keys,
    ) -> Option<ChannelFixture> {
        let community = db.ensure_configured_community(host).await.ok()?.id;
        let creator_keys = Keys::generate();
        let creator_pk = creator_keys.public_key().to_bytes().to_vec();
        let member_pk = member.public_key().to_bytes().to_vec();
        db.ensure_user(community, &creator_pk).await.ok()?;
        db.ensure_user(community, &member_pk).await.ok()?;
        let channel_id = Uuid::new_v4();
        db.create_channel_with_id(
            community,
            channel_id,
            &format!("ch-{}", channel_id.simple()),
            buzz_db::channel::ChannelType::Stream,
            visibility,
            None,
            &creator_pk,
            None,
        )
        .await
        .ok()?;
        db.add_member(
            community,
            channel_id,
            &member_pk,
            buzz_core::channel::MemberRole::Member,
            Some(&creator_pk),
        )
        .await
        .ok()?;
        Some(ChannelFixture {
            community,
            channel_id,
            member_keys: member.clone(),
        })
    }

    /// Insert a channel-scoped text note authored by `author`.
    async fn insert_message(
        db: &buzz_db::Db,
        fixture: &ChannelFixture,
        author: &Keys,
    ) -> Option<EventId> {
        insert_message_with_content(db, fixture, author, "hello from relay_access test").await
    }

    /// [`insert_message`] with explicit content — distinct content is required
    /// for two messages from the same author in the same second, otherwise the
    /// deterministic Schnorr signature makes them byte-identical duplicates.
    async fn insert_message_with_content(
        db: &buzz_db::Db,
        fixture: &ChannelFixture,
        author: &Keys,
        content: &str,
    ) -> Option<EventId> {
        let event = EventBuilder::new(Kind::TextNote, content)
            .sign_with_keys(author)
            .ok()?;
        db.insert_event(fixture.community, &event, Some(fixture.channel_id))
            .await
            .ok()?;
        Some(event.id)
    }

    /// Insert a kind-1 text note with an explicit `created_at` into a channel.
    async fn insert_message_at(
        db: &buzz_db::Db,
        fixture: &ChannelFixture,
        author: &Keys,
        created_at: u64,
    ) -> Option<EventId> {
        let event = EventBuilder::new(Kind::TextNote, format!("msg-{created_at}"))
            .custom_created_at(nostr::Timestamp::from(created_at))
            .sign_with_keys(author)
            .ok()?;
        db.insert_event(fixture.community, &event, Some(fixture.channel_id))
            .await
            .ok()?;
        Some(event.id)
    }

    /// Insert a reply with explicit thread metadata (parent + root).
    #[allow(clippy::too_many_arguments)]
    async fn insert_reply(
        db: &buzz_db::Db,
        fixture: &ChannelFixture,
        author: &Keys,
        parent: &EventId,
        parent_created_at: u64,
        root: &EventId,
        root_created_at: u64,
        created_at: u64,
    ) -> Option<EventId> {
        let event = EventBuilder::new(Kind::TextNote, format!("reply-{created_at}"))
            .tags([Tag::parse(["e", &parent.to_hex(), "", "reply"]).expect("e tag")])
            .custom_created_at(nostr::Timestamp::from(created_at))
            .sign_with_keys(author)
            .ok()?;
        let meta = buzz_db::event::ThreadMetadataParams {
            event_id: event.id.as_bytes(),
            event_created_at: DateTime::from_timestamp(created_at as i64, 0).expect("ts"),
            channel_id: fixture.channel_id,
            parent_event_id: Some(parent.as_bytes()),
            parent_event_created_at: Some(
                DateTime::from_timestamp(parent_created_at as i64, 0).expect("ts"),
            ),
            root_event_id: Some(root.as_bytes()),
            root_event_created_at: Some(
                DateTime::from_timestamp(root_created_at as i64, 0).expect("ts"),
            ),
            depth: 1,
            broadcast: false,
        };
        db.insert_event_with_thread_metadata(
            fixture.community,
            &event,
            Some(fixture.channel_id),
            Some(meta),
        )
        .await
        .ok()?;
        Some(event.id)
    }

    /// Standard NIP-98 Authorization header for a POST to `url` with `body`.
    fn nip98_auth_header(keys: &Keys, url: &str, body: &[u8]) -> String {
        let hash: [u8; 32] = Sha256::digest(body).into();
        let tags = vec![
            Tag::parse(["u", url]).expect("u tag"),
            Tag::parse(["method", "POST"]).expect("method tag"),
            Tag::parse(["payload", hex::encode(hash).as_str()]).expect("payload tag"),
        ];
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags(tags)
            .sign_with_keys(keys)
            .expect("sign NIP-98 event");
        let event_json = serde_json::to_string(&event).expect("serialize NIP-98 event");
        let encoded = BASE64.encode(event_json.as_bytes());
        format!("Nostr {encoded}")
    }

    /// Drive one POST /api/v1/relay/access/check through the router.
    async fn post_check(
        ts: &TestState,
        host: &str,
        keys: &Keys,
        body: Value,
    ) -> axum::response::Response {
        post_access(ts, host, keys, body, ACCESS_CHECK_PATH).await
    }

    /// Drive one POST /api/v1/relay/access/check-batch through the router.
    async fn post_batch(
        ts: &TestState,
        host: &str,
        keys: &Keys,
        body: Value,
    ) -> axum::response::Response {
        post_access(ts, host, keys, body, ACCESS_CHECK_BATCH_PATH).await
    }

    /// Drive one POST to an access endpoint, signing the NIP-98 `u` tag for
    /// the exact `path` and `host`.
    async fn post_access(
        ts: &TestState,
        host: &str,
        keys: &Keys,
        body: Value,
        path: &str,
    ) -> axum::response::Response {
        let body_str = body.to_string();
        let url = format!("https://{host}{path}");
        let auth = nip98_auth_header(keys, &url, body_str.as_bytes());
        build_router(ts.state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header(header::HOST, host)
                    .header(header::AUTHORIZATION, auth)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body_str))
                    .expect("request"),
            )
            .await
            .expect("response")
    }

    async fn read_json(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("read response body");
        serde_json::from_slice(&bytes).expect("response JSON")
    }

    /// NIP-98 Authorization header for a GET — contract: no `payload` tag.
    fn nip98_get_auth_header(keys: &Keys, url: &str) -> String {
        let tags = vec![
            Tag::parse(["u", url]).expect("u tag"),
            Tag::parse(["method", "GET"]).expect("method tag"),
        ];
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags(tags)
            .sign_with_keys(keys)
            .expect("sign NIP-98 event");
        let event_json = serde_json::to_string(&event).expect("serialize NIP-98 event");
        let encoded = BASE64.encode(event_json.as_bytes());
        format!("Nostr {encoded}")
    }

    /// Drive one GET /api/v1/relay/channels?pubkey=<hex> through the router,
    /// signing the exact URL including the query string.
    async fn get_channels(
        ts: &TestState,
        host: &str,
        keys: &Keys,
        pubkey_hex: &str,
    ) -> axum::response::Response {
        let path = format!("/api/v1/relay/channels?pubkey={pubkey_hex}");
        let url = format!("https://{host}{path}");
        let auth = nip98_get_auth_header(keys, &url);
        build_router(ts.state.clone())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path)
                    .header(header::HOST, host)
                    .header(header::AUTHORIZATION, auth)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response")
    }

    /// Drive one GET /api/v1/relay/state/events?<query> through the router,
    /// signing the exact URL including the query string. `query` may be empty
    /// for no query string.
    async fn get_state_events(
        ts: &TestState,
        host: &str,
        keys: &Keys,
        query: &str,
    ) -> axum::response::Response {
        let path = if query.is_empty() {
            "/api/v1/relay/state/events".to_string()
        } else {
            format!("/api/v1/relay/state/events?{query}")
        };
        let url = format!("https://{host}{path}");
        let auth = nip98_get_auth_header(keys, &url);
        build_router(ts.state.clone())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path)
                    .header(header::HOST, host)
                    .header(header::AUTHORIZATION, auth)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response")
    }

    /// Parse the signed event's `content` field (a JSON string) into a Value.
    async fn response_content(response: axum::response::Response) -> Value {
        let body = read_json(response).await;
        let raw = body["content"]
            .as_str()
            .expect("content is a JSON string field");
        serde_json::from_str(raw).expect("content parses as JSON")
    }

    fn check_body(subject_hex: &str, channel_id: &Uuid, message_id: Option<&EventId>) -> Value {
        json!({
            "pubkey": subject_hex,
            "channel_id": channel_id.to_string(),
            "channel_kind": "workspace",
            "message_id": message_id.map(|m| m.to_hex()),
            "event_created_at": null,
        })
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn member_with_existing_message_is_allowed() {
        let host = format!("relay-access-allow-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let fixture = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Open,
        )
        .await
        .expect("channel");
        let message = insert_message(&ts.state.db, &fixture, &fixture.member_keys)
            .await
            .expect("message");

        let response = post_check(
            &ts,
            &host,
            &ts.service_keys,
            check_body(
                &fixture.member_keys.public_key().to_hex(),
                &fixture.channel_id,
                Some(&message),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let content = response_content(response).await;
        assert_eq!(content["decision"], "allow");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn non_member_is_denied_without_revealing_membership() {
        let host = format!("relay-access-deny-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let fixture = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Private,
        )
        .await
        .expect("channel");
        let message = insert_message(&ts.state.db, &fixture, &fixture.member_keys)
            .await
            .expect("message");
        let stranger = Keys::generate();

        let response = post_check(
            &ts,
            &host,
            &ts.service_keys,
            check_body(
                &stranger.public_key().to_hex(),
                &fixture.channel_id,
                Some(&message),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let content = response_content(response).await;
        assert_eq!(content["decision"], "deny");
        assert_eq!(content["reason"], "not a member");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn unknown_channel_is_not_found() {
        let host = format!("relay-access-unknown-ch-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let member = Keys::generate();

        let response = post_check(
            &ts,
            &host,
            &ts.service_keys,
            check_body(
                &member.public_key().to_hex(),
                &Uuid::new_v4(),
                Some(&EventId::all_zeros()),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let content = response_content(response).await;
        assert_eq!(content["decision"], "not_found");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn deleted_or_unknown_message_is_not_found() {
        let host = format!("relay-access-msg-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let fixture = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Open,
        )
        .await
        .expect("channel");
        let message = insert_message(&ts.state.db, &fixture, &fixture.member_keys)
            .await
            .expect("message");
        let subject_hex = fixture.member_keys.public_key().to_hex();

        // Unknown message id → not_found.
        let response = post_check(
            &ts,
            &host,
            &ts.service_keys,
            check_body(
                &subject_hex,
                &fixture.channel_id,
                Some(&EventId::all_zeros()),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let content = response_content(response).await;
        assert_eq!(content["decision"], "not_found");

        // Soft-deleted message → not_found.
        ts.state
            .db
            .soft_delete_event(fixture.community, &message.to_bytes())
            .await
            .expect("soft delete");
        let response = post_check(
            &ts,
            &host,
            &ts.service_keys,
            check_body(&subject_hex, &fixture.channel_id, Some(&message)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let content = response_content(response).await;
        assert_eq!(content["decision"], "not_found");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn message_in_other_channel_is_not_found() {
        let host = format!("relay-access-xch-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let channel_a = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Private,
        )
        .await
        .expect("channel A");
        let channel_b = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Private,
        )
        .await
        .expect("channel B");
        // The message exists only in channel B.
        let message_b = insert_message(&ts.state.db, &channel_b, &channel_b.member_keys)
            .await
            .expect("message B");

        // Member of channel A asks about channel A with B's message id — the
        // message must NOT be found (and must not reveal it exists elsewhere).
        let response = post_check(
            &ts,
            &host,
            &ts.service_keys,
            check_body(
                &channel_a.member_keys.public_key().to_hex(),
                &channel_a.channel_id,
                Some(&message_b),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let content = response_content(response).await;
        assert_eq!(content["decision"], "not_found");
        assert_eq!(content["reason"], "not found");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn cross_community_host_is_not_found() {
        let host_a = format!("relay-access-a-{}.test", Uuid::new_v4().simple());
        let host_b = format!("relay-access-b-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host_a).await.expect("test state");
        let fixture = seed_channel(
            &ts.state.db,
            &host_a,
            buzz_db::channel::ChannelVisibility::Open,
        )
        .await
        .expect("channel");
        let message = insert_message(&ts.state.db, &fixture, &fixture.member_keys)
            .await
            .expect("message");
        // Host B is a configured community that has no channel — the same
        // channel id must NOT resolve there.
        ts.state
            .db
            .ensure_configured_community(&host_b)
            .await
            .expect("community B");

        let response = post_check(
            &ts,
            &host_b,
            &ts.service_keys,
            check_body(
                &fixture.member_keys.public_key().to_hex(),
                &fixture.channel_id,
                Some(&message),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let content = response_content(response).await;
        assert_eq!(content["decision"], "not_found");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn untrusted_caller_is_unauthorized() {
        let host = format!("relay-access-trust-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let fixture = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Open,
        )
        .await
        .expect("channel");
        let message = insert_message(&ts.state.db, &fixture, &fixture.member_keys)
            .await
            .expect("message");
        let impostor = Keys::generate();

        let response = post_check(
            &ts,
            &host,
            &impostor,
            check_body(
                &fixture.member_keys.public_key().to_hex(),
                &fixture.channel_id,
                Some(&message),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn empty_allowlist_fails_closed() {
        let host = format!("relay-access-empty-allow-{}.test", Uuid::new_v4().simple());
        // The config default: no trusted service pubkeys → the authorization
        // API is disabled and EVERY caller, even with a valid NIP-98 signature,
        // must get 401.
        let service_keys = Keys::generate();
        let ts = access_check_test_state_with_allowlist(&host, service_keys, vec![])
            .await
            .expect("test state");

        let response = post_check(
            &ts,
            &host,
            &ts.service_keys,
            check_body(
                &Keys::generate().public_key().to_hex(),
                &Uuid::new_v4(),
                None,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn missing_or_malformed_nip98_is_unauthorized() {
        let host = format!("relay-access-nip98-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let body = check_body(
            &Keys::generate().public_key().to_hex(),
            &Uuid::new_v4(),
            None,
        )
        .to_string();

        // No Authorization header at all.
        let response = build_router(ts.state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/relay/access/check")
                    .header(header::HOST, &host)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.clone()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Malformed base64 / garbage in the Nostr auth header.
        let response = build_router(ts.state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/relay/access/check")
                    .header(header::HOST, &host)
                    .header(header::AUTHORIZATION, "Nostr !!!not-base64!!!")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn payload_tag_mismatch_is_unauthorized() {
        let host = format!("relay-access-payload-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let body = check_body(
            &Keys::generate().public_key().to_hex(),
            &Uuid::new_v4(),
            None,
        )
        .to_string();
        let url = format!("https://{host}/api/v1/relay/access/check");
        // Signed over a DIFFERENT body than the one actually sent.
        let auth = nip98_auth_header(&ts.service_keys, &url, b"{\"different\":true}");

        let response = build_router(ts.state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/relay/access/check")
                    .header(header::HOST, &host)
                    .header(header::AUTHORIZATION, auth)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn response_is_signed_event_echoing_request() {
        let host = format!("relay-access-verify-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let fixture = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Open,
        )
        .await
        .expect("channel");
        let message = insert_message(&ts.state.db, &fixture, &fixture.member_keys)
            .await
            .expect("message");
        let subject_hex = fixture.member_keys.public_key().to_hex();
        let channel_str = fixture.channel_id.to_string();
        let message_hex = message.to_hex();

        let response = post_check(
            &ts,
            &host,
            &ts.service_keys,
            json!({
                "pubkey": subject_hex,
                "channel_id": channel_str,
                "channel_kind": "dm",
                "message_id": message_hex,
                "event_created_at": 1700000000,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("read response body");
        let raw = String::from_utf8(bytes.to_vec()).expect("response is UTF-8");
        let event: nostr::Event = serde_json::from_str(&raw).expect("response is a Nostr event");
        assert_eq!(
            event.kind,
            Kind::Custom(KIND_RELAY_AUTHZ_RESPONSE as u16),
            "kind must be 19030"
        );
        assert_eq!(event.pubkey, ts.relay_pubkey, "signed by the relay key");
        event.verify().expect("event id and signature must verify");

        let content: Value = serde_json::from_str(&event.content).expect("content is JSON");
        assert_eq!(content["decision"], "allow");
        assert_eq!(content["reason"], "allowed");
        assert_eq!(content["pubkey"], subject_hex, "echoes request pubkey");
        assert_eq!(
            content["channel_id"], channel_str,
            "echoes request channel_id"
        );
        assert_eq!(
            content["message_id"], message_hex,
            "echoes request message_id"
        );
        let evaluated_at = content["evaluated_at"]
            .as_i64()
            .expect("evaluated_at is unix seconds");
        let now = nostr::Timestamp::now().as_secs() as i64;
        assert!(
            (now - evaluated_at).abs() <= 60,
            "evaluated_at must be recent; got {evaluated_at}, now {now}"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn channel_level_check_without_message_id() {
        let host = format!("relay-access-level-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let fixture = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Private,
        )
        .await
        .expect("channel");
        // Member, message exists, but NO message_id → channel-level allow.
        let body = json!({
            "pubkey": fixture.member_keys.public_key().to_hex(),
            "channel_id": fixture.channel_id.to_string(),
            "channel_kind": "private",
        });
        let response = post_check(&ts, &host, &ts.service_keys, body).await;
        assert_eq!(response.status(), StatusCode::OK);
        let content = response_content(response).await;
        assert_eq!(content["decision"], "allow");
        assert!(content["message_id"].is_null());
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn batch_mixed_decisions_order_preserved_and_echoed() {
        let host = format!("relay-batch-mixed-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let channel = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Private,
        )
        .await
        .expect("channel");
        let live_message = insert_message(&ts.state.db, &channel, &channel.member_keys)
            .await
            .expect("live message");
        let deleted_message =
            insert_message_with_content(&ts.state.db, &channel, &channel.member_keys, "deleted")
                .await
                .expect("message to delete");
        ts.state
            .db
            .soft_delete_event(channel.community, &deleted_message.to_bytes())
            .await
            .expect("soft delete");
        let member_hex = channel.member_keys.public_key().to_hex();
        let stranger_hex = Keys::generate().public_key().to_hex();
        let unknown_channel = Uuid::new_v4();

        let items = vec![
            check_body(&member_hex, &channel.channel_id, Some(&live_message)),
            check_body(&stranger_hex, &channel.channel_id, Some(&live_message)),
            check_body(&stranger_hex, &unknown_channel, None),
            check_body(&member_hex, &channel.channel_id, Some(&deleted_message)),
        ];

        let response = post_batch(&ts, &host, &ts.service_keys, json!({ "checks": items })).await;
        assert_eq!(response.status(), StatusCode::OK);
        let content = response_content(response).await;
        let results = content["results"].as_array().expect("results array");
        assert_eq!(results.len(), 4, "one result per check, order preserved");

        let expected: [(Value, &str, &str); 4] = [
            (json!("allow"), "allowed", "member + live message"),
            (json!("deny"), "not a member", "non-member"),
            (json!("not_found"), "not found", "unknown channel"),
            (json!("not_found"), "not found", "deleted message"),
        ];
        for (i, (decision, reason, label)) in expected.iter().enumerate() {
            let result = &results[i];
            assert_eq!(&result["decision"], decision, "item {i} ({label}) decision");
            assert_eq!(result["reason"], *reason, "item {i} ({label}) reason");
            // Verbatim echo of pubkey / channel_id / message_id per item.
            assert_eq!(
                result["pubkey"], items[i]["pubkey"],
                "item {i} ({label}) echoes pubkey"
            );
            assert_eq!(
                result["channel_id"], items[i]["channel_id"],
                "item {i} ({label}) echoes channel_id"
            );
            assert_eq!(
                result["message_id"], items[i]["message_id"],
                "item {i} ({label}) echoes message_id"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn batch_decisions_match_single_check_decisions() {
        let host = format!("relay-batch-parity-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let channel = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Private,
        )
        .await
        .expect("channel");
        let message = insert_message(&ts.state.db, &channel, &channel.member_keys)
            .await
            .expect("message");
        let member_hex = channel.member_keys.public_key().to_hex();
        let stranger_hex = Keys::generate().public_key().to_hex();
        let unknown_channel = Uuid::new_v4();

        let items = vec![
            check_body(&member_hex, &channel.channel_id, Some(&message)),
            check_body(&stranger_hex, &channel.channel_id, Some(&message)),
            check_body(&stranger_hex, &unknown_channel, None),
            check_body(&member_hex, &channel.channel_id, None),
        ];

        let response = post_batch(&ts, &host, &ts.service_keys, json!({ "checks": items })).await;
        assert_eq!(response.status(), StatusCode::OK);
        let batch_content = response_content(response).await;
        let results = batch_content["results"]
            .as_array()
            .expect("results array")
            .clone();

        for (i, item) in items.iter().enumerate() {
            let single =
                response_content(post_check(&ts, &host, &ts.service_keys, item.clone()).await)
                    .await;
            assert_eq!(
                single["decision"], results[i]["decision"],
                "item {i}: batch decision must match single-check decision"
            );
            assert_eq!(
                single["reason"], results[i]["reason"],
                "item {i}: batch reason must match single-check reason"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn batch_over_64_checks_is_bad_request() {
        let host = format!("relay-batch-cap-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let item = check_body(
            &Keys::generate().public_key().to_hex(),
            &Uuid::new_v4(),
            None,
        );
        let items = vec![item; 65];

        let response = post_batch(&ts, &host, &ts.service_keys, json!({ "checks": items })).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn batch_malformed_item_is_bad_request() {
        let host = format!("relay-batch-malformed-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        // One item with a wrong field type — the whole request is malformed.
        let items = json!([
            {
                "pubkey": 123,
                "channel_id": Uuid::new_v4().to_string(),
                "channel_kind": "workspace",
                "message_id": null,
            }
        ]);

        let response = post_batch(&ts, &host, &ts.service_keys, json!({ "checks": items })).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn batch_deny_item_does_not_affect_other_items() {
        let host = format!("relay-batch-isolation-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let channel_a = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Private,
        )
        .await
        .expect("channel A");
        let channel_b = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Private,
        )
        .await
        .expect("channel B");
        let message_a = insert_message(&ts.state.db, &channel_a, &channel_a.member_keys)
            .await
            .expect("message A");
        let message_b = insert_message(&ts.state.db, &channel_b, &channel_b.member_keys)
            .await
            .expect("message B");
        let stranger_hex = Keys::generate().public_key().to_hex();

        let items = vec![
            check_body(
                &channel_a.member_keys.public_key().to_hex(),
                &channel_a.channel_id,
                Some(&message_a),
            ),
            check_body(&stranger_hex, &channel_a.channel_id, Some(&message_a)),
            check_body(
                &channel_b.member_keys.public_key().to_hex(),
                &channel_b.channel_id,
                Some(&message_b),
            ),
        ];

        let response = post_batch(&ts, &host, &ts.service_keys, json!({ "checks": items })).await;
        assert_eq!(response.status(), StatusCode::OK);
        let content = response_content(response).await;
        let results = content["results"].as_array().expect("results array");
        assert_eq!(results.len(), 3);
        assert_eq!(results[0]["decision"], "allow");
        assert_eq!(results[1]["decision"], "deny");
        assert_eq!(
            results[2]["decision"], "allow",
            "deny item must not affect neighbors"
        );
        assert_eq!(results[2]["reason"], "allowed");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn batch_untrusted_caller_is_unauthorized() {
        let host = format!("relay-batch-trust-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let impostor = Keys::generate();

        let response = post_batch(
            &ts,
            &host,
            &impostor,
            json!({ "checks": [check_body(&Keys::generate().public_key().to_hex(), &Uuid::new_v4(), None)] }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn batch_response_is_signed_event_with_mirrored_evaluated_at() {
        let host = format!("relay-batch-envelope-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let channel = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Private,
        )
        .await
        .expect("channel");
        let message = insert_message(&ts.state.db, &channel, &channel.member_keys)
            .await
            .expect("message");
        let items = vec![
            check_body(
                &channel.member_keys.public_key().to_hex(),
                &channel.channel_id,
                Some(&message),
            ),
            check_body(
                &Keys::generate().public_key().to_hex(),
                &channel.channel_id,
                Some(&message),
            ),
        ];

        let response = post_batch(&ts, &host, &ts.service_keys, json!({ "checks": items })).await;
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("read response body");
        let raw = String::from_utf8(bytes.to_vec()).expect("response is UTF-8");
        let event: nostr::Event = serde_json::from_str(&raw).expect("response is a Nostr event");
        assert_eq!(
            event.kind,
            Kind::Custom(KIND_RELAY_AUTHZ_RESPONSE as u16),
            "kind must be 19030"
        );
        assert_eq!(event.pubkey, ts.relay_pubkey, "signed by the relay key");
        event.verify().expect("event id and signature must verify");

        let content: Value = serde_json::from_str(&event.content).expect("content is JSON");
        let envelope_at = content["evaluated_at"]
            .as_i64()
            .expect("top-level evaluated_at is unix seconds");
        let now = nostr::Timestamp::now().as_secs() as i64;
        assert!(
            (now - envelope_at).abs() <= 60,
            "evaluated_at must be recent; got {envelope_at}, now {now}"
        );
        let results = content["results"].as_array().expect("results array");
        assert_eq!(results.len(), 2);
        for (i, result) in results.iter().enumerate() {
            assert_eq!(
                result["evaluated_at"].as_i64(),
                Some(envelope_at),
                "item {i} evaluated_at must mirror the envelope value"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn batch_empty_checks_yields_empty_results() {
        let host = format!("relay-batch-empty-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");

        let response = post_batch(&ts, &host, &ts.service_keys, json!({ "checks": [] })).await;
        assert_eq!(response.status(), StatusCode::OK);
        let content = response_content(response).await;
        assert_eq!(
            content["results"].as_array().expect("results array").len(),
            0
        );
        assert!(
            content["evaluated_at"].as_i64().is_some(),
            "empty batch still carries the freshness authority"
        );
    }

    /// Map channel_id → entry from a registry response `content`.
    fn registry_map(content: &Value) -> std::collections::HashMap<String, &Value> {
        content["channels"]
            .as_array()
            .expect("channels array")
            .iter()
            .map(|entry| {
                (
                    entry["channel_id"]
                        .as_str()
                        .expect("channel_id string")
                        .to_string(),
                    entry,
                )
            })
            .collect()
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn registry_member_sees_private_and_open_with_member_flags() {
        let host = format!("relay-channels-member-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let subject = Keys::generate();
        let private_ch = seed_channel_with_member(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Private,
            &subject,
        )
        .await
        .expect("private member channel");
        let open_member = seed_channel_with_member(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Open,
            &subject,
        )
        .await
        .expect("open member channel");
        let open_nonmember = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Open,
        )
        .await
        .expect("open non-member channel");
        let private_other = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Private,
        )
        .await
        .expect("private other channel");

        let response =
            get_channels(&ts, &host, &ts.service_keys, &subject.public_key().to_hex()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let content = response_content(response).await;
        let by_id = registry_map(&content);

        let priv_entry = by_id
            .get(&private_ch.channel_id.to_string())
            .expect("private member channel must be listed");
        assert_eq!(priv_entry["member"], true);
        assert_eq!(priv_entry["visibility"], "private");

        let open_entry = by_id
            .get(&open_member.channel_id.to_string())
            .expect("open member channel must be listed");
        assert_eq!(open_entry["member"], true);
        assert_eq!(open_entry["visibility"], "open");

        let open_nm_entry = by_id
            .get(&open_nonmember.channel_id.to_string())
            .expect("open non-member channel must be listed");
        assert_eq!(open_nm_entry["member"], false);

        assert!(
            !by_id.contains_key(&private_other.channel_id.to_string()),
            "private channel the subject is not a member of must be absent"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn registry_non_member_sees_only_open_channels() {
        let host = format!("relay-channels-nonmember-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let subject = Keys::generate();
        let private_ch = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Private,
        )
        .await
        .expect("private channel");
        let open_ch = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Open,
        )
        .await
        .expect("open channel");

        let response =
            get_channels(&ts, &host, &ts.service_keys, &subject.public_key().to_hex()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let content = response_content(response).await;
        let by_id = registry_map(&content);

        let open_entry = by_id
            .get(&open_ch.channel_id.to_string())
            .expect("open channel must be listed for a non-member");
        assert_eq!(open_entry["member"], false);

        assert!(
            !by_id.contains_key(&private_ch.channel_id.to_string()),
            "private channel must be absent for a non-member"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn registry_dm_and_hidden_channels_of_others_absent() {
        let host = format!("relay-channels-dm-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let community = ts
            .state
            .db
            .ensure_configured_community(&host)
            .await
            .expect("community")
            .id;
        let subject = Keys::generate();
        let other_a = Keys::generate();
        let other_b = Keys::generate();
        let subject_pk = subject.public_key().to_bytes();
        let a_pk = other_a.public_key().to_bytes();
        let b_pk = other_b.public_key().to_bytes();
        // DM between two other users — the subject must never see it.
        let dm_other = ts
            .state
            .db
            .create_dm(community, &[&a_pk, &b_pk], &a_pk)
            .await
            .expect("DM of other users");
        // Visible DM the subject participates in — must be listed.
        let dm_visible = ts
            .state
            .db
            .create_dm(community, &[&subject_pk, &a_pk], &subject_pk)
            .await
            .expect("visible DM");
        // DM the subject participates in but has hidden — must be absent.
        let dm_hidden = ts
            .state
            .db
            .create_dm(community, &[&subject_pk, &b_pk], &subject_pk)
            .await
            .expect("hidden DM");
        ts.state
            .db
            .hide_dm(community, dm_hidden.id, &subject_pk)
            .await
            .expect("hide DM");

        let response =
            get_channels(&ts, &host, &ts.service_keys, &subject.public_key().to_hex()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let content = response_content(response).await;
        let by_id = registry_map(&content);

        assert!(
            !by_id.contains_key(&dm_other.id.to_string()),
            "a DM the subject is not part of must be absent"
        );
        assert!(
            !by_id.contains_key(&dm_hidden.id.to_string()),
            "a DM the subject has hidden must be absent"
        );
        let visible = by_id
            .get(&dm_visible.id.to_string())
            .expect("visible DM must be listed");
        assert_eq!(visible["member"], true);
        assert_eq!(visible["channel_type"], "dm");
        assert_eq!(visible["visibility"], "private");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn registry_cross_community_excludes_other_community() {
        let host_a = format!("relay-channels-a-{}.test", Uuid::new_v4().simple());
        let host_b = format!("relay-channels-b-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host_a).await.expect("test state");
        let member = seed_channel(
            &ts.state.db,
            &host_a,
            buzz_db::channel::ChannelVisibility::Open,
        )
        .await
        .expect("channel in A");
        ts.state
            .db
            .ensure_configured_community(&host_b)
            .await
            .expect("community B");

        // Request Host = community B — A's channels must never be included.
        let response = get_channels(
            &ts,
            &host_b,
            &ts.service_keys,
            &member.member_keys.public_key().to_hex(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let content = response_content(response).await;
        assert_eq!(
            content["channels"]
                .as_array()
                .expect("channels array")
                .len(),
            0,
            "another community's channels must never be listed"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn registry_untrusted_caller_is_unauthorized() {
        let host = format!("relay-channels-trust-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let impostor = Keys::generate();

        let response = get_channels(
            &ts,
            &host,
            &impostor,
            &Keys::generate().public_key().to_hex(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn registry_malformed_or_missing_pubkey_is_bad_request() {
        let host = format!("relay-channels-query-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");

        // Malformed (non-hex) pubkey parameter.
        let response = get_channels(&ts, &host, &ts.service_keys, "not-a-pubkey").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Missing pubkey parameter entirely (query absent from the signed URL).
        let path = "/api/v1/relay/channels";
        let url = format!("https://{host}{path}");
        let auth = nip98_get_auth_header(&ts.service_keys, &url);
        let response = build_router(ts.state.clone())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path)
                    .header(header::HOST, &host)
                    .header(header::AUTHORIZATION, auth)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn registry_response_is_signed_event_with_all_fields() {
        let host = format!("relay-channels-verify-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let subject = Keys::generate();
        seed_channel_with_member(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Open,
            &subject,
        )
        .await
        .expect("member channel");
        let subject_hex = subject.public_key().to_hex();

        let response = get_channels(&ts, &host, &ts.service_keys, &subject_hex).await;
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("read response body");
        let raw = String::from_utf8(bytes.to_vec()).expect("response is UTF-8");
        let event: nostr::Event = serde_json::from_str(&raw).expect("response is a Nostr event");
        assert_eq!(
            event.kind,
            Kind::Custom(KIND_RELAY_AUTHZ_RESPONSE as u16),
            "kind must be 19030"
        );
        assert_eq!(event.pubkey, ts.relay_pubkey, "signed by the relay key");
        event.verify().expect("event id and signature must verify");

        let content: Value = serde_json::from_str(&event.content).expect("content is JSON");
        assert_eq!(content["pubkey"], subject_hex, "echoes the query pubkey");
        let evaluated_at = content["evaluated_at"]
            .as_i64()
            .expect("evaluated_at is unix seconds");
        let now = nostr::Timestamp::now().as_secs() as i64;
        assert!(
            (now - evaluated_at).abs() <= 60,
            "evaluated_at must be recent; got {evaluated_at}, now {now}"
        );
        let channels = content["channels"].as_array().expect("channels array");
        assert!(!channels.is_empty());
        for entry in channels {
            assert!(entry["channel_id"].is_string(), "channel_id present");
            assert!(entry["name"].is_string(), "name present");
            assert!(entry["channel_type"].is_string(), "channel_type present");
            assert!(entry["visibility"].is_string(), "visibility present");
            assert!(entry["member"].is_boolean(), "member present");
        }
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn registry_no_channels_yields_empty_list() {
        let host = format!("relay-channels-empty-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let stranger = Keys::generate();

        let response = get_channels(
            &ts,
            &host,
            &ts.service_keys,
            &stranger.public_key().to_hex(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let content = response_content(response).await;
        assert_eq!(
            content["channels"]
                .as_array()
                .expect("channels array")
                .len(),
            0
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn state_pages_cover_all_events_without_dupes_ascending() {
        let host = format!("relay-state-paging-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let channel = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Open,
        )
        .await
        .expect("channel");
        let base = nostr::Timestamp::now().as_secs() - 120;
        let mut seeded = Vec::new();
        for i in 0..5 {
            seeded.push(
                insert_message_at(&ts.state.db, &channel, &channel.member_keys, base + i)
                    .await
                    .expect("message"),
            );
        }

        let mut seen_ids: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        let mut pages = 0;
        let mut prev_created_at: Option<i64> = None;
        loop {
            let query = match &cursor {
                Some(c) => format!("limit=2&cursor={c}"),
                None => "limit=2".to_string(),
            };
            let response = get_state_events(&ts, &host, &ts.service_keys, &query).await;
            assert_eq!(response.status(), StatusCode::OK);
            let content = response_content(response).await;
            let entries = content["entries"].as_array().expect("entries array");
            pages += 1;
            assert!(entries.len() <= 2, "page {pages} must respect limit=2");
            for entry in entries {
                let created_at = entry["event"]["created_at"]
                    .as_i64()
                    .expect("created_at on raw event");
                if let Some(prev) = prev_created_at {
                    assert!(created_at > prev, "created_at must ascend across pages");
                }
                prev_created_at = Some(created_at);
                let id = entry["context"]["message_id"]
                    .as_str()
                    .expect("message_id")
                    .to_string();
                assert!(
                    !seen_ids.contains(&id),
                    "event {id} must not appear twice across pages"
                );
                seen_ids.push(id);
            }
            if content["complete"].as_bool().expect("complete") {
                assert!(
                    content["cursor"].is_null(),
                    "final page must have cursor: null"
                );
                break;
            }
            cursor = Some(
                content["cursor"]
                    .as_str()
                    .expect("non-final page has a cursor")
                    .to_string(),
            );
            assert!(pages <= 10, "paging must terminate");
        }

        assert_eq!(pages, 3, "5 events at limit=2 needs 3 pages");
        assert_eq!(seen_ids.len(), 5, "all seeded events seen exactly once");
        for id in &seeded {
            assert!(
                seen_ids.contains(&id.to_hex()),
                "seeded event {id} must be paged"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn state_since_filters_on_own_created_at() {
        let host = format!("relay-state-since-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let channel = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Open,
        )
        .await
        .expect("channel");
        let base = nostr::Timestamp::now().as_secs() - 120;
        let mut seeded = Vec::new();
        for i in 0..4 {
            seeded.push(
                insert_message_at(&ts.state.db, &channel, &channel.member_keys, base + i * 10)
                    .await
                    .expect("message"),
            );
        }
        let since = base + 15; // only the +20 and +30 events qualify

        let response =
            get_state_events(&ts, &host, &ts.service_keys, &format!("since={since}")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let content = response_content(response).await;
        let entries = content["entries"].as_array().expect("entries array");
        assert_eq!(
            entries.len(),
            2,
            "since must filter on the event's own created_at"
        );
        let ids: Vec<String> = entries
            .iter()
            .map(|e| e["context"]["message_id"].as_str().expect("id").to_string())
            .collect();
        assert!(ids.contains(&seeded[2].to_hex()));
        assert!(ids.contains(&seeded[3].to_hex()));
        assert!(content["complete"].as_bool().expect("complete"));
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn state_context_shape_and_channel_kind_mapping() {
        let host = format!("relay-state-context-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let community = ts
            .state
            .db
            .ensure_configured_community(&host)
            .await
            .expect("community")
            .id;
        let member_a = Keys::generate();
        let member_b = Keys::generate();
        let a_pk = member_a.public_key().to_bytes();
        let b_pk = member_b.public_key().to_bytes();
        let dm = ts
            .state
            .db
            .create_dm(community, &[&a_pk, &b_pk], &a_pk)
            .await
            .expect("dm channel");
        let private_ch = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Private,
        )
        .await
        .expect("private channel");
        let open_ch = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Open,
        )
        .await
        .expect("open channel");

        let base = nostr::Timestamp::now().as_secs() - 120;
        let dm_fixture = ChannelFixture {
            community,
            channel_id: dm.id,
            member_keys: member_a.clone(),
        };
        let dm_msg = insert_message_at(&ts.state.db, &dm_fixture, &member_a, base)
            .await
            .expect("dm message");
        let priv_msg =
            insert_message_at(&ts.state.db, &private_ch, &private_ch.member_keys, base + 1)
                .await
                .expect("private message");
        let open_msg = insert_message_at(&ts.state.db, &open_ch, &open_ch.member_keys, base + 2)
            .await
            .expect("open message");
        let reply = insert_reply(
            &ts.state.db,
            &open_ch,
            &open_ch.member_keys,
            &open_msg,
            base + 2,
            &open_msg,
            base + 2,
            base + 3,
        )
        .await
        .expect("reply");

        let response = get_state_events(&ts, &host, &ts.service_keys, "limit=10").await;
        assert_eq!(response.status(), StatusCode::OK);
        let content = response_content(response).await;
        let entries = content["entries"].as_array().expect("entries array");
        assert_eq!(entries.len(), 4);

        for entry in entries {
            let ctx = &entry["context"];
            assert!(ctx["community_id"].is_string());
            assert!(ctx["channel_id"].is_string());
            assert!(ctx["channel_kind"].is_string());
            assert!(ctx["thread_root_id"].is_null() || ctx["thread_root_id"].is_string());
            assert!(ctx["message_id"].is_string());
            assert!(ctx["event_type"].is_string());
            assert!(
                ctx["supersedes_event_id"].is_null(),
                "supersedes_event_id is always null in v1alpha1"
            );
            assert_eq!(ctx["community_id"], community.to_string());
            assert_eq!(ctx["message_id"], entry["event"]["id"]);
        }

        let dm_entry = entries
            .iter()
            .find(|e| e["context"]["message_id"] == dm_msg.to_hex())
            .expect("dm entry");
        assert_eq!(dm_entry["context"]["channel_kind"], "dm");
        assert_eq!(dm_entry["context"]["channel_id"], dm.id.to_string());
        assert!(dm_entry["context"]["thread_root_id"].is_null());

        let priv_entry = entries
            .iter()
            .find(|e| e["context"]["message_id"] == priv_msg.to_hex())
            .expect("private entry");
        assert_eq!(priv_entry["context"]["channel_kind"], "private");
        assert_eq!(
            priv_entry["context"]["channel_id"],
            private_ch.channel_id.to_string()
        );
        assert!(priv_entry["context"]["thread_root_id"].is_null());

        let open_entry = entries
            .iter()
            .find(|e| e["context"]["message_id"] == open_msg.to_hex())
            .expect("open entry");
        assert_eq!(open_entry["context"]["channel_kind"], "workspace");
        assert!(open_entry["context"]["thread_root_id"].is_null());

        let reply_entry = entries
            .iter()
            .find(|e| e["context"]["message_id"] == reply.to_hex())
            .expect("reply entry");
        assert_eq!(reply_entry["context"]["channel_kind"], "workspace");
        assert_eq!(
            reply_entry["context"]["thread_root_id"],
            open_msg.to_hex(),
            "reply must carry its thread root"
        );
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn state_deleted_event_included_with_deleted_type() {
        let host = format!("relay-state-deleted-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let channel = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Open,
        )
        .await
        .expect("channel");
        let base = nostr::Timestamp::now().as_secs() - 120;
        let first = insert_message_at(&ts.state.db, &channel, &channel.member_keys, base)
            .await
            .expect("first message");
        insert_message_at(&ts.state.db, &channel, &channel.member_keys, base + 1)
            .await
            .expect("second message");
        ts.state
            .db
            .soft_delete_event(channel.community, &first.to_bytes())
            .await
            .expect("soft delete");

        let response = get_state_events(&ts, &host, &ts.service_keys, "").await;
        assert_eq!(response.status(), StatusCode::OK);
        let content = response_content(response).await;
        let entries = content["entries"].as_array().expect("entries array");
        assert_eq!(entries.len(), 2, "tombstoned events must still be paged");
        let deleted_entry = entries
            .iter()
            .find(|e| e["context"]["message_id"] == first.to_hex())
            .expect("deleted event entry");
        assert_eq!(deleted_entry["context"]["event_type"], "deleted");
        let live_entry = entries
            .iter()
            .find(|e| e["context"]["message_id"] != first.to_hex())
            .expect("live event entry");
        assert_eq!(live_entry["context"]["event_type"], "created");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn state_limit_is_clamped_not_errored() {
        let host = format!("relay-state-limit-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let channel = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Open,
        )
        .await
        .expect("channel");
        let base = nostr::Timestamp::now().as_secs() - 120;
        for i in 0..3 {
            insert_message_at(&ts.state.db, &channel, &channel.member_keys, base + i)
                .await
                .expect("message");
        }

        // limit=0 → clamped to 1 (no error).
        let response = get_state_events(&ts, &host, &ts.service_keys, "limit=0").await;
        assert_eq!(response.status(), StatusCode::OK);
        let content = response_content(response).await;
        assert_eq!(content["entries"].as_array().expect("entries").len(), 1);

        // limit=10000 → clamped to 500 (no error; 3 events fit).
        let response = get_state_events(&ts, &host, &ts.service_keys, "limit=10000").await;
        assert_eq!(response.status(), StatusCode::OK);
        let content = response_content(response).await;
        let entries = content["entries"].as_array().expect("entries");
        assert!(entries.len() <= 500);
        assert_eq!(entries.len(), 3);
        assert!(content["complete"].as_bool().expect("complete"));
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn state_malformed_cursor_and_auth_failures() {
        let host = format!("relay-state-auth-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");

        // Malformed cursor: not base64.
        let response =
            get_state_events(&ts, &host, &ts.service_keys, "cursor=%%%not-base64%%%").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Malformed cursor: base64 of garbage without the separator.
        let garbage = BASE64.encode("not-a-cursor");
        let response =
            get_state_events(&ts, &host, &ts.service_keys, &format!("cursor={garbage}")).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Missing Authorization header.
        let response = build_router(ts.state.clone())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/relay/state/events")
                    .header(header::HOST, &host)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Untrusted caller.
        let impostor = Keys::generate();
        let response = get_state_events(&ts, &host, &impostor, "").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn state_cross_community_excludes_other_community() {
        let host_a = format!("relay-state-a-{}.test", Uuid::new_v4().simple());
        let host_b = format!("relay-state-b-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host_a).await.expect("test state");
        let channel = seed_channel(
            &ts.state.db,
            &host_a,
            buzz_db::channel::ChannelVisibility::Open,
        )
        .await
        .expect("channel in A");
        insert_message_at(
            &ts.state.db,
            &channel,
            &channel.member_keys,
            nostr::Timestamp::now().as_secs() - 10,
        )
        .await
        .expect("message in A");
        ts.state
            .db
            .ensure_configured_community(&host_b)
            .await
            .expect("community B");

        let response = get_state_events(&ts, &host_b, &ts.service_keys, "").await;
        assert_eq!(response.status(), StatusCode::OK);
        let content = response_content(response).await;
        assert_eq!(
            content["entries"].as_array().expect("entries").len(),
            0,
            "another community's events must never be paged"
        );
        assert!(content["complete"].as_bool().expect("complete"));
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn state_response_is_signed_event_with_verifiable_events() {
        let host = format!("relay-state-verify-{}.test", Uuid::new_v4().simple());
        let ts = access_check_test_state(&host).await.expect("test state");
        let channel = seed_channel(
            &ts.state.db,
            &host,
            buzz_db::channel::ChannelVisibility::Open,
        )
        .await
        .expect("channel");
        let message = insert_message_at(
            &ts.state.db,
            &channel,
            &channel.member_keys,
            nostr::Timestamp::now().as_secs() - 10,
        )
        .await
        .expect("message");

        let response = get_state_events(&ts, &host, &ts.service_keys, "").await;
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("read response body");
        let raw = String::from_utf8(bytes.to_vec()).expect("response is UTF-8");
        let envelope: nostr::Event = serde_json::from_str(&raw).expect("response is a Nostr event");
        assert_eq!(
            envelope.kind,
            Kind::Custom(KIND_RELAY_AUTHZ_RESPONSE as u16),
            "kind must be 19030"
        );
        assert_eq!(envelope.pubkey, ts.relay_pubkey, "signed by the relay key");
        envelope
            .verify()
            .expect("event id and signature must verify");

        let content: Value = serde_json::from_str(&envelope.content).expect("content is JSON");
        assert!(
            content["evaluated_at"].is_null(),
            "state/events content has no evaluated_at field"
        );
        let entries = content["entries"].as_array().expect("entries array");
        assert_eq!(entries.len(), 1);
        let raw_event: nostr::Event =
            serde_json::from_value(entries[0]["event"].clone()).expect("entry event parses");
        assert_eq!(raw_event.kind, Kind::TextNote, "entry is a kind-1 event");
        assert_eq!(
            raw_event.id, message,
            "entry event id matches the seeded event"
        );
        raw_event
            .verify()
            .expect("entry event id and signature must verify");
    }
}
