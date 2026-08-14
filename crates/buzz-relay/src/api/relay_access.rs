//! Relay authorization API — `POST /api/v1/relay/access/check`.
//!
//! Lets a provisioned trusted service workload (which never holds a human
//! user's signing key) ask the relay whether a given pubkey may currently read
//! a given channel/message. The decision derives exclusively from the relay's
//! own state (channel visibility, membership, message availability); the
//! request's `channel_kind` is never trusted.
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

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
};
use serde::Deserialize;
use serde_json::Value;

use buzz_core::kind::KIND_RELAY_AUTHZ_RESPONSE;
use buzz_db::DbError;

use crate::state::AppState;

use super::bridge::{
    check_nip98_replay, enforce_http_admission, nip98_expected_url, verify_bridge_auth,
};
use super::{api_error, internal_error};

/// The endpoint path — the NIP-98 `u` tag must match the exact request URL.
const ACCESS_CHECK_PATH: &str = "/api/v1/relay/access/check";

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

    let evaluated_at = nostr::Timestamp::now().as_secs() as i64;

    // Channel lookup from the relay's own state; unknown or soft-deleted
    // channels are indistinguishable (`ChannelNotFound`).
    let channel = match state.db.get_channel(tenant.community(), channel_id).await {
        Ok(ch) => ch,
        Err(DbError::ChannelNotFound(_)) => {
            return decision_response(&state, evaluated_at, Decision::NotFound, "not found", &req);
        }
        Err(e) => return Err(internal_error(&format!("channel lookup failed: {e}"))),
    };

    // Readability: an active member, or an open channel anyone may read.
    let subject_bytes = subject_pubkey.to_bytes();
    let is_member = state
        .db
        .is_member(tenant.community(), channel_id, &subject_bytes)
        .await
        .map_err(|e| internal_error(&format!("membership check failed: {e}")))?;
    if !is_member && channel.visibility != "open" {
        // Existence hiding: never reveal who is or is not a member.
        return decision_response(&state, evaluated_at, Decision::Deny, "not a member", &req);
    }

    // Message-level availability, when a message id was given. The message
    // must exist, be non-deleted, and belong to the checked channel; anything
    // else is `not_found` (never reveals the message exists elsewhere).
    match message_id_bytes {
        Some(id_bytes) => {
            let stored = state
                .db
                .get_event_by_id(tenant.community(), &id_bytes)
                .await
                .map_err(|e| internal_error(&format!("event lookup failed: {e}")))?;
            match stored {
                Some(se) if se.channel_id == Some(channel_id) => {
                    decision_response(&state, evaluated_at, Decision::Allow, "allowed", &req)
                }
                _ => decision_response(&state, evaluated_at, Decision::NotFound, "not found", &req),
            }
        }
        None => decision_response(&state, evaluated_at, Decision::Allow, "allowed", &req),
    }
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
    /// tests). Returns `None` when Postgres is unavailable.
    async fn access_check_test_state(host: &str) -> Option<TestState> {
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

        let service_keys = Keys::generate();
        config.relay_trusted_service_pubkeys = vec![service_keys.public_key().to_hex()];

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
    /// creator is bootstrapped as owner.
    async fn seed_channel(
        db: &buzz_db::Db,
        host: &str,
        visibility: buzz_db::channel::ChannelVisibility,
    ) -> Option<ChannelFixture> {
        let community = db.ensure_configured_community(host).await.ok()?.id;
        let creator_keys = Keys::generate();
        let member_keys = Keys::generate();
        let creator_pk = creator_keys.public_key().to_bytes().to_vec();
        let member_pk = member_keys.public_key().to_bytes().to_vec();
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
            member_keys,
        })
    }

    /// Insert a channel-scoped text note authored by `author`.
    async fn insert_message(
        db: &buzz_db::Db,
        fixture: &ChannelFixture,
        author: &Keys,
    ) -> Option<EventId> {
        let event = EventBuilder::new(Kind::TextNote, "hello from relay_access test")
            .sign_with_keys(author)
            .ok()?;
        db.insert_event(fixture.community, &event, Some(fixture.channel_id))
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
        let body_str = body.to_string();
        let url = format!("https://{host}/api/v1/relay/access/check");
        let auth = nip98_auth_header(keys, &url, body_str.as_bytes());
        build_router(ts.state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/relay/access/check")
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
}
