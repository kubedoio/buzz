//! Regression tests for guest-role write authorization on channel messages
//! (kind:9 / KIND_STREAM_MESSAGE).
//!
//! The relay's role model (`buzz_core::channel::MemberRole`) defines `Guest`
//! as a read-only external participant: a guest holds an active
//! `channel_members` row, but every channel write must be denied. The
//! write-path membership gate must consult the member's role, not just row
//! presence, on every event — a previously established session or a warm
//! membership cache must not grandfather writes after a member→guest
//! downgrade.
//!
//! Requires a running relay. Ignored by default:
//!   RELAY_URL=ws://localhost:3030 \
//!   DATABASE_URL=postgres://buzz:buzz_dev@localhost:5471/buzz \
//!   cargo test -p buzz-test-client --test regression_guest_write_denial \
//!     -- --ignored --nocapture

use nostr::{Event, EventBuilder, Keys, Kind, Tag};

fn relay_url() -> String {
    std::env::var("RELAY_URL").unwrap_or_else(|_| "ws://localhost:3000".to_string())
}

fn host() -> String {
    relay_url()
        .trim_start_matches("wss://")
        .trim_start_matches("ws://")
        .trim_end_matches('/')
        .to_string()
}

async fn e2e_db_pool() -> sqlx::Pool<sqlx::Postgres> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://buzz:buzz_dev@localhost:5432/buzz".to_string());
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("connect to e2e Postgres")
}

/// Ensure the community row matching this relay's Host header exists, so
/// tenant resolution binds the connection to a real community.
async fn ensure_test_community() -> uuid::Uuid {
    let pool = e2e_db_pool().await;
    let id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO communities (id, host) \
         VALUES ($1, $2) \
         ON CONFLICT (lower(host)) DO NOTHING",
    )
    .bind(id)
    .bind(host())
    .execute(&pool)
    .await
    .unwrap_or_else(|e| panic!("seed community: {e}"));
    sqlx::query_scalar("SELECT id FROM communities WHERE lower(host) = lower($1)")
        .bind(host())
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("lookup community: {e}"))
}

/// Create a channel over WebSocket and return the channel UUID.
async fn create_channel_ws(
    client: &mut buzz_test_client::BuzzTestClient,
    keys: &Keys,
    visibility: &str,
) -> String {
    let channel_uuid = uuid::Uuid::new_v4().to_string();
    let channel_name = format!("guest-denial-{}", channel_uuid);
    let event = EventBuilder::new(Kind::Custom(9007), "")
        .tags(vec![
            Tag::parse(["h", &channel_uuid]).unwrap(),
            Tag::parse(["name", &channel_name]).unwrap(),
            Tag::parse(["channel_type", "stream"]).unwrap(),
            Tag::parse(["visibility", visibility]).unwrap(),
        ])
        .sign_with_keys(keys)
        .unwrap();
    let ok = client.send_event(event).await.expect("create channel");
    assert!(ok.accepted, "channel creation failed: {}", ok.message);
    channel_uuid
}

/// Submit a kind:9000 PUT_USER event over WebSocket.
async fn put_user_ws(
    client: &mut buzz_test_client::BuzzTestClient,
    channel_id: &str,
    target_pubkey_hex: &str,
    role: Option<&str>,
    signer: &Keys,
) -> (bool, String) {
    let mut tags = vec![
        Tag::parse(["h", channel_id]).unwrap(),
        Tag::parse(["p", target_pubkey_hex]).unwrap(),
    ];
    if let Some(role) = role {
        tags.push(Tag::parse(["role", role]).unwrap());
    }
    let event = EventBuilder::new(Kind::Custom(9000), "")
        .tags(tags)
        .sign_with_keys(signer)
        .unwrap();
    let ok = client.send_event(event).await.expect("send PUT_USER");
    (ok.accepted, ok.message)
}

/// Submit a kind:9001 REMOVE_USER event over WebSocket.
async fn remove_user_ws(
    client: &mut buzz_test_client::BuzzTestClient,
    channel_id: &str,
    target_pubkey_hex: &str,
    signer: &Keys,
) -> (bool, String) {
    let event = EventBuilder::new(Kind::Custom(9001), "")
        .tags(vec![
            Tag::parse(["h", channel_id]).unwrap(),
            Tag::parse(["p", target_pubkey_hex]).unwrap(),
        ])
        .sign_with_keys(signer)
        .unwrap();
    let ok = client.send_event(event).await.expect("send REMOVE_USER");
    (ok.accepted, ok.message)
}

/// Sign a kind:9 channel message.
fn stream_message(keys: &Keys, channel_id: &str, content: &str) -> Event {
    EventBuilder::new(Kind::Custom(9), content)
        .tags(vec![Tag::parse(["h", channel_id]).unwrap()])
        .sign_with_keys(keys)
        .unwrap()
}

/// A guest-role identity must not be able to post a kind:9 message,
/// even though it holds an active channel membership row.
#[tokio::test]
#[ignore]
async fn test_guest_cannot_post_stream_message() {
    let url = relay_url();
    ensure_test_community().await;
    let owner_keys = Keys::generate();
    let guest_keys = Keys::generate();

    let mut owner = buzz_test_client::BuzzTestClient::connect(&url, &owner_keys)
        .await
        .expect("connect as owner");
    let channel_id = create_channel_ws(&mut owner, &owner_keys, "private").await;

    let (accepted, msg) = put_user_ws(
        &mut owner,
        &channel_id,
        &guest_keys.public_key().to_hex(),
        Some("guest"),
        &owner_keys,
    )
    .await;
    assert!(accepted, "owner should add guest, got: {msg}");

    let mut guest = buzz_test_client::BuzzTestClient::connect(&url, &guest_keys)
        .await
        .expect("connect as guest");
    let ok = guest
        .send_event(stream_message(
            &guest_keys,
            &channel_id,
            "guest write attempt",
        ))
        .await
        .expect("guest kind:9 publish");
    assert!(
        !ok.accepted,
        "guest kind:9 must be rejected, but it was accepted: {}",
        ok.message
    );
    assert!(
        ok.message.contains("guest") || ok.message.contains("read-only"),
        "rejection should name the guest read-only restriction, got: {}",
        ok.message
    );

    // Control: the owner's own kind:9 is still accepted in the same channel.
    let ok = owner
        .send_event(stream_message(&owner_keys, &channel_id, "owner write"))
        .await
        .expect("owner kind:9 publish");
    assert!(ok.accepted, "owner kind:9 must be accepted: {}", ok.message);

    owner.disconnect().await.expect("disconnect owner");
    guest.disconnect().await.expect("disconnect guest");
}

/// The guest denial must also hold on open channels: guests are read-only
/// participants, and the open-channel nonmember fallback must not widen
/// guest access.
#[tokio::test]
#[ignore]
async fn test_guest_cannot_post_stream_message_open_channel() {
    let url = relay_url();
    ensure_test_community().await;
    let owner_keys = Keys::generate();
    let guest_keys = Keys::generate();

    let mut owner = buzz_test_client::BuzzTestClient::connect(&url, &owner_keys)
        .await
        .expect("connect as owner");
    let channel_id = create_channel_ws(&mut owner, &owner_keys, "open").await;

    let (accepted, msg) = put_user_ws(
        &mut owner,
        &channel_id,
        &guest_keys.public_key().to_hex(),
        Some("guest"),
        &owner_keys,
    )
    .await;
    assert!(accepted, "owner should add guest, got: {msg}");

    let mut guest = buzz_test_client::BuzzTestClient::connect(&url, &guest_keys)
        .await
        .expect("connect as guest");
    let ok = guest
        .send_event(stream_message(
            &guest_keys,
            &channel_id,
            "guest write attempt",
        ))
        .await
        .expect("guest kind:9 publish");
    assert!(
        !ok.accepted,
        "guest kind:9 on an open channel must be rejected, but it was accepted: {}",
        ok.message
    );

    owner.disconnect().await.expect("disconnect owner");
    guest.disconnect().await.expect("disconnect guest");
}

/// A regular member and an admin must retain write access (the fix must not
/// over-deny).
#[tokio::test]
#[ignore]
async fn test_member_can_post_stream_message() {
    let url = relay_url();
    ensure_test_community().await;
    let owner_keys = Keys::generate();
    let member_keys = Keys::generate();
    let admin_keys = Keys::generate();

    let mut owner = buzz_test_client::BuzzTestClient::connect(&url, &owner_keys)
        .await
        .expect("connect as owner");
    let channel_id = create_channel_ws(&mut owner, &owner_keys, "private").await;

    let (accepted, msg) = put_user_ws(
        &mut owner,
        &channel_id,
        &member_keys.public_key().to_hex(),
        Some("member"),
        &owner_keys,
    )
    .await;
    assert!(accepted, "owner should add member, got: {msg}");
    let (accepted, msg) = put_user_ws(
        &mut owner,
        &channel_id,
        &admin_keys.public_key().to_hex(),
        Some("admin"),
        &owner_keys,
    )
    .await;
    assert!(accepted, "owner should add admin, got: {msg}");

    let mut member = buzz_test_client::BuzzTestClient::connect(&url, &member_keys)
        .await
        .expect("connect as member");
    let ok = member
        .send_event(stream_message(&member_keys, &channel_id, "member write"))
        .await
        .expect("member kind:9 publish");
    assert!(
        ok.accepted,
        "member kind:9 must be accepted: {}",
        ok.message
    );

    let mut admin = buzz_test_client::BuzzTestClient::connect(&url, &admin_keys)
        .await
        .expect("connect as admin");
    let ok = admin
        .send_event(stream_message(&admin_keys, &channel_id, "admin write"))
        .await
        .expect("admin kind:9 publish");
    assert!(ok.accepted, "admin kind:9 must be accepted: {}", ok.message);

    owner.disconnect().await.expect("disconnect owner");
    member.disconnect().await.expect("disconnect member");
    admin.disconnect().await.expect("disconnect admin");
}

/// Downgrading a member to guest must cut off writes immediately — the role
/// is re-read from the database per event, so a live session established
/// while the identity still held the member role cannot keep writing.
#[tokio::test]
#[ignore]
async fn test_member_downgraded_to_guest_is_denied_on_live_session() {
    let url = relay_url();
    ensure_test_community().await;
    let owner_keys = Keys::generate();
    let member_keys = Keys::generate();

    let mut owner = buzz_test_client::BuzzTestClient::connect(&url, &owner_keys)
        .await
        .expect("connect as owner");
    let channel_id = create_channel_ws(&mut owner, &owner_keys, "private").await;

    let (accepted, msg) = put_user_ws(
        &mut owner,
        &channel_id,
        &member_keys.public_key().to_hex(),
        Some("member"),
        &owner_keys,
    )
    .await;
    assert!(accepted, "owner should add member, got: {msg}");

    // The member connects and posts while holding the member role.
    let mut member = buzz_test_client::BuzzTestClient::connect(&url, &member_keys)
        .await
        .expect("connect as member");
    let ok = member
        .send_event(stream_message(
            &member_keys,
            &channel_id,
            "pre-downgrade write",
        ))
        .await
        .expect("pre-downgrade kind:9 publish");
    assert!(
        ok.accepted,
        "member kind:9 must be accepted: {}",
        ok.message
    );

    // Owner downgrades the same identity to guest on the wire.
    let (accepted, msg) = put_user_ws(
        &mut owner,
        &channel_id,
        &member_keys.public_key().to_hex(),
        Some("guest"),
        &owner_keys,
    )
    .await;
    assert!(
        accepted,
        "owner should downgrade member to guest, got: {msg}"
    );

    // Same connection, no re-auth: the very next write must be denied.
    let ok = member
        .send_event(stream_message(
            &member_keys,
            &channel_id,
            "post-downgrade write",
        ))
        .await
        .expect("post-downgrade kind:9 publish");
    assert!(
        !ok.accepted,
        "kind:9 after member→guest downgrade must be rejected on the live session: {}",
        ok.message
    );

    owner.disconnect().await.expect("disconnect owner");
    member.disconnect().await.expect("disconnect member");
}

/// A removed (soft-removed) member must not be able to post to a private
/// channel — removal revocation is enforced on the write path.
#[tokio::test]
#[ignore]
async fn test_removed_member_cannot_post_stream_message() {
    let url = relay_url();
    ensure_test_community().await;
    let owner_keys = Keys::generate();
    let member_keys = Keys::generate();

    let mut owner = buzz_test_client::BuzzTestClient::connect(&url, &owner_keys)
        .await
        .expect("connect as owner");
    let channel_id = create_channel_ws(&mut owner, &owner_keys, "private").await;

    let (accepted, msg) = put_user_ws(
        &mut owner,
        &channel_id,
        &member_keys.public_key().to_hex(),
        Some("member"),
        &owner_keys,
    )
    .await;
    assert!(accepted, "owner should add member, got: {msg}");

    // Owner removes the member while its session is live.
    let (accepted, msg) = remove_user_ws(
        &mut owner,
        &channel_id,
        &member_keys.public_key().to_hex(),
        &owner_keys,
    )
    .await;
    assert!(accepted, "owner should remove member, got: {msg}");

    let mut member = buzz_test_client::BuzzTestClient::connect(&url, &member_keys)
        .await
        .expect("connect as removed member");
    let ok = member
        .send_event(stream_message(
            &member_keys,
            &channel_id,
            "post-removal write",
        ))
        .await
        .expect("removed member kind:9 publish");
    assert!(
        !ok.accepted,
        "removed member kind:9 must be rejected: {}",
        ok.message
    );

    owner.disconnect().await.expect("disconnect owner");
    member.disconnect().await.expect("disconnect member");
}

/// A nonmember must not be able to post to a private channel.
#[tokio::test]
#[ignore]
async fn test_private_channel_nonmember_cannot_post_stream_message() {
    let url = relay_url();
    ensure_test_community().await;
    let owner_keys = Keys::generate();
    let stranger_keys = Keys::generate();

    let mut owner = buzz_test_client::BuzzTestClient::connect(&url, &owner_keys)
        .await
        .expect("connect as owner");
    let channel_id = create_channel_ws(&mut owner, &owner_keys, "private").await;

    let mut stranger = buzz_test_client::BuzzTestClient::connect(&url, &stranger_keys)
        .await
        .expect("connect as stranger");
    let ok = stranger
        .send_event(stream_message(
            &stranger_keys,
            &channel_id,
            "nonmember private write",
        ))
        .await
        .expect("nonmember kind:9 publish");
    assert!(
        !ok.accepted,
        "nonmember kind:9 to a private channel must be rejected: {}",
        ok.message
    );

    owner.disconnect().await.expect("disconnect owner");
    stranger.disconnect().await.expect("disconnect stranger");
}

/// Open-channel nonmember writes are an existing, documented behavior of
/// this fork (NOSTR.md: open channels remain readable/writable by non-members
/// at runtime). The guest fix must not change it.
#[tokio::test]
#[ignore]
async fn test_open_channel_nonmember_can_post_stream_message() {
    let url = relay_url();
    ensure_test_community().await;
    let owner_keys = Keys::generate();
    let stranger_keys = Keys::generate();

    let mut owner = buzz_test_client::BuzzTestClient::connect(&url, &owner_keys)
        .await
        .expect("connect as owner");
    let channel_id = create_channel_ws(&mut owner, &owner_keys, "open").await;

    let mut stranger = buzz_test_client::BuzzTestClient::connect(&url, &stranger_keys)
        .await
        .expect("connect as stranger");
    let ok = stranger
        .send_event(stream_message(
            &stranger_keys,
            &channel_id,
            "open-channel nonmember write",
        ))
        .await
        .expect("nonmember kind:9 publish");
    assert!(
        ok.accepted,
        "open-channel nonmember kind:9 must stay accepted (documented fork behavior): {}",
        ok.message
    );

    owner.disconnect().await.expect("disconnect owner");
    stranger.disconnect().await.expect("disconnect stranger");
}
