//! Regression tests for guest-role write authorization on channel-scoped
//! writes: channel messages (kind:9 / KIND_STREAM_MESSAGE), channel metadata
//! edits (kind:9002 topic/purpose and the privileged name/about/archived/
//! visibility/ttl tags), message edits (kind:40003 self-edit), message
//! deletes (kind:9005 self-delete), huddle audio admission (speaking is a
//! channel write, including parent-linked ephemeral huddles), channel-scoped
//! command events (kind:30620 workflow definitions, kind:41011 DM
//! add-member), NIP-09 kind:5 deletions of addressable and regular targets,
//! and the durable indirect write a workflow performs through its owner's
//! standing authority (the send_message action sink posting a relay-signed
//! kind:9).
//!
//! The relay's role model (`buzz_core::channel::MemberRole`) defines `Guest`
//! as a read-only external participant: a guest holds an active
//! `channel_members` row, but every channel write must be denied. The
//! write-path membership gate must consult the member's role, not just row
//! presence, on every event — a previously established session or a warm
//! membership cache must not grandfather writes after a member→guest
//! downgrade or a removal.
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

/// Record that `human` owns `agent` (`users.agent_owner_pubkey`). The human's
/// own users row must exist first: agent_owner_pubkey is a self-referencing
/// foreign key.
async fn seed_agent_owner(
    pool: &sqlx::Pool<sqlx::Postgres>,
    community_id: uuid::Uuid,
    agent_keys: &Keys,
    human_keys: &Keys,
) {
    sqlx::query(
        "INSERT INTO users (community_id, pubkey) \
         VALUES ($1, $2) \
         ON CONFLICT (community_id, pubkey) DO NOTHING",
    )
    .bind(community_id)
    .bind(human_keys.public_key().to_bytes())
    .execute(pool)
    .await
    .expect("seed human user row");
    sqlx::query(
        "INSERT INTO users (community_id, pubkey, agent_owner_pubkey) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (community_id, pubkey) \
         DO UPDATE SET agent_owner_pubkey = EXCLUDED.agent_owner_pubkey",
    )
    .bind(community_id)
    .bind(agent_keys.public_key().to_bytes())
    .bind(human_keys.public_key().to_bytes())
    .execute(pool)
    .await
    .expect("seed agent ownership");
}

/// Sign a kind:9 channel message.
fn stream_message(keys: &Keys, channel_id: &str, content: &str) -> Event {
    EventBuilder::new(Kind::Custom(9), content)
        .tags(vec![Tag::parse(["h", channel_id]).unwrap()])
        .sign_with_keys(keys)
        .unwrap()
}

/// Sign a kind:9002 channel-metadata edit carrying only a topic tag
/// (the "any member" branch — no privileged name/about/etc. tags).
fn edit_metadata_topic(keys: &Keys, channel_id: &str, topic: &str) -> Event {
    EventBuilder::new(Kind::Custom(9002), "")
        .tags(vec![
            Tag::parse(["h", channel_id]).unwrap(),
            Tag::parse(["topic", topic]).unwrap(),
        ])
        .sign_with_keys(keys)
        .unwrap()
}

/// Sign a kind:40003 edit of `target_id` (referenced via e tag).
fn stream_message_edit(keys: &Keys, channel_id: &str, target_id: &str, content: &str) -> Event {
    EventBuilder::new(Kind::Custom(40003), content)
        .tags(vec![
            Tag::parse(["h", channel_id]).unwrap(),
            Tag::parse(["e", target_id]).unwrap(),
        ])
        .sign_with_keys(keys)
        .unwrap()
}

/// Sign a kind:9005 delete of `target_id` (referenced via e tag).
fn delete_event(keys: &Keys, channel_id: &str, target_id: &str) -> Event {
    EventBuilder::new(Kind::Custom(9005), "")
        .tags(vec![
            Tag::parse(["h", channel_id]).unwrap(),
            Tag::parse(["e", target_id]).unwrap(),
        ])
        .sign_with_keys(keys)
        .unwrap()
}

/// YAML body for a workflow definition with a single `send_message` step.
/// `text` uniquely marks the message the workflow would post, so tests can
/// assert on its presence/absence in the events table.
fn workflow_send_message_yaml(name: &str, text: &str) -> String {
    format!(
        "name: {name}\n\
         description: guest-write-denial regression probe\n\
         trigger:\n\
         \x20 on: webhook\n\
         steps:\n\
         \x20 - id: step1\n\
         \x20   name: Notify\n\
         \x20   action: send_message\n\
         \x20   text: \"{text}\"\n"
    )
}

/// Sign a kind:30620 workflow definition for `workflow_id` in `channel_id`.
fn workflow_def(keys: &Keys, channel_id: &str, workflow_id: &str, name: &str, text: &str) -> Event {
    EventBuilder::new(Kind::Custom(30620), workflow_send_message_yaml(name, text))
        .tags(vec![
            Tag::parse(["h", channel_id]).unwrap(),
            Tag::parse(["d", workflow_id]).unwrap(),
            Tag::parse(["name", name]).unwrap(),
        ])
        .sign_with_keys(keys)
        .unwrap()
}

/// Sign a kind:46020 manual workflow trigger for `workflow_id`.
fn workflow_trigger(keys: &Keys, workflow_id: &str) -> Event {
    EventBuilder::new(Kind::Custom(46020), "")
        .tags(vec![Tag::parse(["d", workflow_id]).unwrap()])
        .sign_with_keys(keys)
        .unwrap()
}

/// Sign a kind:41010 DM open with `other` as the sole other participant.
fn dm_open(keys: &Keys, other_pubkey_hex: &str) -> Event {
    EventBuilder::new(Kind::Custom(41010), "")
        .tags(vec![Tag::parse(["p", other_pubkey_hex]).unwrap()])
        .sign_with_keys(keys)
        .unwrap()
}

/// Sign a kind:41011 DM add-member command.
fn dm_add_member(keys: &Keys, channel_id: &str, new_member_hex: &str) -> Event {
    EventBuilder::new(Kind::Custom(41011), "")
        .tags(vec![
            Tag::parse(["h", channel_id]).unwrap(),
            Tag::parse(["p", new_member_hex]).unwrap(),
        ])
        .sign_with_keys(keys)
        .unwrap()
}

/// Parse a command `response:{"channel_id":"…"}` OK message into the channel id.
fn parse_response_channel_id(message: &str, what: &str) -> String {
    let json_part = message
        .strip_prefix("response:")
        .unwrap_or_else(|| panic!("{what} OK message missing `response:` prefix: {message:?}"));
    let resp: serde_json::Value = serde_json::from_str(json_part)
        .unwrap_or_else(|e| panic!("parse {what} response json: {e} ({json_part:?})"));
    resp["channel_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{what} response missing channel_id: {resp}"))
        .to_string()
}

/// Poll the events table until a kind:9 carrying exactly `text` in
/// `channel_id` appears, or the timeout elapses. Returns whether it appeared.
async fn wait_for_channel_message(
    pool: &sqlx::Pool<sqlx::Postgres>,
    community_id: uuid::Uuid,
    channel_id: &str,
    text: &str,
    timeout: std::time::Duration,
) -> bool {
    let channel_uuid = uuid::Uuid::parse_str(channel_id).expect("channel UUID");
    let start = std::time::Instant::now();
    loop {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM events \
             WHERE community_id = $1 AND channel_id = $2 AND kind = 9 \
               AND content = $3 AND deleted_at IS NULL",
        )
        .bind(community_id)
        .bind(channel_uuid)
        .bind(text)
        .fetch_one(pool)
        .await
        .expect("count workflow-posted kind:9 rows");
        if count > 0 {
            return true;
        }
        if start.elapsed() > timeout {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
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

/// A guest-role identity must not be able to edit channel metadata with a
/// kind:9002 event carrying only topic/purpose tags — the "any member"
/// branch must apply the same guest read-only rule as the generic gate.
#[tokio::test]
#[ignore]
async fn test_guest_cannot_edit_channel_topic() {
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
        .send_event(edit_metadata_topic(
            &guest_keys,
            &channel_id,
            "guest topic override",
        ))
        .await
        .expect("guest kind:9002 publish");
    assert!(
        !ok.accepted,
        "guest kind:9002 topic edit must be rejected, but it was accepted: {}",
        ok.message
    );
    assert!(
        ok.message.contains("guest") || ok.message.contains("read-only"),
        "rejection should name the guest read-only restriction, got: {}",
        ok.message
    );

    // Control: the owner's own kind:9002 topic edit is still accepted.
    let ok = owner
        .send_event(edit_metadata_topic(&owner_keys, &channel_id, "owner topic"))
        .await
        .expect("owner kind:9002 publish");
    assert!(
        ok.accepted,
        "owner kind:9002 must be accepted: {}",
        ok.message
    );

    owner.disconnect().await.expect("disconnect owner");
    guest.disconnect().await.expect("disconnect guest");
}

/// A guest must not be able to kind:40003-edit a message it authored while
/// it still held the member role — the self-edit author re-gate must consult
/// the current role, not row presence.
#[tokio::test]
#[ignore]
async fn test_guest_cannot_self_edit_own_message() {
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

    let mut member = buzz_test_client::BuzzTestClient::connect(&url, &member_keys)
        .await
        .expect("connect as member");
    let original = stream_message(&member_keys, &channel_id, "original body");
    let ok = member
        .send_event(original.clone())
        .await
        .expect("member kind:9 publish");
    assert!(
        ok.accepted,
        "member kind:9 must be accepted: {}",
        ok.message
    );
    let target_id = original.id.to_hex();

    // Control: while still a member, the author can self-edit.
    let ok = member
        .send_event(stream_message_edit(
            &member_keys,
            &channel_id,
            &target_id,
            "edited while member",
        ))
        .await
        .expect("member kind:40003 publish");
    assert!(
        ok.accepted,
        "member self-edit must be accepted: {}",
        ok.message
    );

    // Owner downgrades the author to guest on the wire.
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

    // Same connection: the guest's self-edit of its own pre-downgrade
    // message must be denied.
    let ok = member
        .send_event(stream_message_edit(
            &member_keys,
            &channel_id,
            &target_id,
            "edited after downgrade",
        ))
        .await
        .expect("guest kind:40003 publish");
    assert!(
        !ok.accepted,
        "guest kind:40003 self-edit must be rejected: {}",
        ok.message
    );
    assert!(
        ok.message.contains("guest") || ok.message.contains("read-only"),
        "rejection should name the guest read-only restriction, got: {}",
        ok.message
    );

    owner.disconnect().await.expect("disconnect owner");
    member.disconnect().await.expect("disconnect member");
}

/// A guest must not be able to kind:9005-delete a message it authored while
/// it still held the member role — the self-delete author re-gate must
/// consult the current role, not row presence.
#[tokio::test]
#[ignore]
async fn test_guest_cannot_self_delete_own_message() {
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

    let mut member = buzz_test_client::BuzzTestClient::connect(&url, &member_keys)
        .await
        .expect("connect as member");
    let original = stream_message(&member_keys, &channel_id, "message to delete");
    let ok = member
        .send_event(original.clone())
        .await
        .expect("member kind:9 publish");
    assert!(
        ok.accepted,
        "member kind:9 must be accepted: {}",
        ok.message
    );
    let target_id = original.id.to_hex();

    // Owner downgrades the author to guest on the wire.
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

    // Same connection: the guest's self-delete of its own pre-downgrade
    // message must be denied.
    let ok = member
        .send_event(delete_event(&member_keys, &channel_id, &target_id))
        .await
        .expect("guest kind:9005 publish");
    assert!(
        !ok.accepted,
        "guest kind:9005 self-delete must be rejected: {}",
        ok.message
    );

    // Control: the owner can still delete the guest's message.
    let ok = owner
        .send_event(delete_event(&owner_keys, &channel_id, &target_id))
        .await
        .expect("owner kind:9005 publish");
    assert!(
        ok.accepted,
        "owner kind:9005 delete must be accepted: {}",
        ok.message
    );

    owner.disconnect().await.expect("disconnect owner");
    member.disconnect().await.expect("disconnect member");
}

/// The `bot` role is a separate designation outside the owner>admin>member>
/// guest hierarchy; the guest read-only rule must not over-deny it. Bots
/// keep their standing write grants (closed role enum guard).
#[tokio::test]
#[ignore]
async fn test_bot_can_post_stream_message() {
    let url = relay_url();
    ensure_test_community().await;
    let owner_keys = Keys::generate();
    let bot_keys = Keys::generate();

    let mut owner = buzz_test_client::BuzzTestClient::connect(&url, &owner_keys)
        .await
        .expect("connect as owner");
    let channel_id = create_channel_ws(&mut owner, &owner_keys, "private").await;

    let (accepted, msg) = put_user_ws(
        &mut owner,
        &channel_id,
        &bot_keys.public_key().to_hex(),
        Some("bot"),
        &owner_keys,
    )
    .await;
    assert!(accepted, "owner should add bot, got: {msg}");

    let mut bot = buzz_test_client::BuzzTestClient::connect(&url, &bot_keys)
        .await
        .expect("connect as bot");
    let ok = bot
        .send_event(stream_message(&bot_keys, &channel_id, "bot write"))
        .await
        .expect("bot kind:9 publish");
    assert!(
        ok.accepted,
        "bot kind:9 must be accepted (bot keeps standing grants): {}",
        ok.message
    );

    owner.disconnect().await.expect("disconnect owner");
    bot.disconnect().await.expect("disconnect bot");
}

/// Removal must revoke writes on a private channel IMMEDIATELY, on the same
/// live session, with no membership-cache window: the write gate reads the
/// role fresh per event, so a just-removed member reads `None` and fails
/// closed instead of riding a stale cached `true` for the 10s moka TTL.
#[tokio::test]
#[ignore]
async fn test_removed_member_denied_immediately_private_channel() {
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

    let mut member = buzz_test_client::BuzzTestClient::connect(&url, &member_keys)
        .await
        .expect("connect as member");
    // Warm every cache the relay consults (membership moka + any read path)
    // from this live session, then get removed, then write again with no
    // delay: a presence-cache fail-open would accept the post here.
    let ok = member
        .send_event(stream_message(
            &member_keys,
            &channel_id,
            "pre-removal write",
        ))
        .await
        .expect("pre-removal kind:9 publish");
    assert!(
        ok.accepted,
        "member kind:9 must be accepted: {}",
        ok.message
    );

    let (accepted, msg) = remove_user_ws(
        &mut owner,
        &channel_id,
        &member_keys.public_key().to_hex(),
        &owner_keys,
    )
    .await;
    assert!(accepted, "owner should remove member, got: {msg}");

    // Same connection, immediately: the very next write must be denied.
    let ok = member
        .send_event(stream_message(
            &member_keys,
            &channel_id,
            "immediate post-removal write",
        ))
        .await
        .expect("immediate post-removal kind:9 publish");
    assert!(
        !ok.accepted,
        "removed member must be denied immediately on a private channel (no cache window): {}",
        ok.message
    );

    owner.disconnect().await.expect("disconnect owner");
    member.disconnect().await.expect("disconnect member");
}

/// A guest must not be able to define a channel-scoped workflow (kind:30620):
/// command events return before the persistent-event write gate, so the
/// command path enforces the shared gate itself. A guest-defined workflow
/// would be a durable indirect write — its actions execute with the owner's
/// standing authority long after the defining event.
#[tokio::test]
#[ignore]
async fn test_guest_cannot_define_workflow() {
    let url = relay_url();
    let community_id = ensure_test_community().await;
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

    let workflow_id = uuid::Uuid::new_v4().to_string();
    let marker = format!("guest-wf-def-probe-{}", uuid::Uuid::new_v4());
    let mut guest = buzz_test_client::BuzzTestClient::connect(&url, &guest_keys)
        .await
        .expect("connect as guest");
    let ok = guest
        .send_event(workflow_def(
            &guest_keys,
            &channel_id,
            &workflow_id,
            "guest-def",
            &marker,
        ))
        .await
        .expect("guest kind:30620 publish");
    assert!(
        !ok.accepted,
        "guest kind:30620 workflow definition must be rejected, but it was accepted: {}",
        ok.message
    );
    assert!(
        ok.message.contains("guest") || ok.message.contains("read-only"),
        "rejection should name the guest read-only restriction, got: {}",
        ok.message
    );

    // Belt and braces: even if a definition somehow landed, its workflow must
    // not be able to post into the channel.
    let pool = e2e_db_pool().await;
    let appeared = wait_for_channel_message(
        &pool,
        community_id,
        &channel_id,
        &marker,
        std::time::Duration::from_secs(3),
    )
    .await;
    assert!(
        !appeared,
        "no workflow message may land in the channel from a guest definition"
    );

    // Control: the owner's own definition in the same channel is accepted.
    let workflow_id = uuid::Uuid::new_v4().to_string();
    let ok = owner
        .send_event(workflow_def(
            &owner_keys,
            &channel_id,
            &workflow_id,
            "owner-def",
            &format!("owner-wf-def-probe-{}", uuid::Uuid::new_v4()),
        ))
        .await
        .expect("owner kind:30620 publish");
    assert!(
        ok.accepted,
        "owner kind:30620 workflow definition must be accepted: {}",
        ok.message
    );

    owner.disconnect().await.expect("disconnect owner");
    guest.disconnect().await.expect("disconnect guest");
}

/// A workflow owned by an identity that was downgraded to guest must not run:
/// manual triggers re-check the owner's CURRENT role, and a guest is
/// read-only. Most importantly, the workflow's send_message action sink must
/// not persist a relay-signed kind:9 with the guest's standing authority.
#[tokio::test]
#[ignore]
async fn test_guest_triggered_workflow_cannot_post_channel_message() {
    let url = relay_url();
    let community_id = ensure_test_community().await;
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

    // The member defines a workflow whose single action posts a marked
    // kind:9 into the channel.
    let workflow_id = uuid::Uuid::new_v4().to_string();
    let marker = format!("guest-wf-run-probe-{}", uuid::Uuid::new_v4());
    let mut member = buzz_test_client::BuzzTestClient::connect(&url, &member_keys)
        .await
        .expect("connect as member");
    let ok = member
        .send_event(workflow_def(
            &member_keys,
            &channel_id,
            &workflow_id,
            "member-def",
            &marker,
        ))
        .await
        .expect("member kind:30620 publish");
    assert!(
        ok.accepted,
        "member kind:30620 workflow definition must be accepted: {}",
        ok.message
    );

    // Owner downgrades the workflow owner to guest on the wire.
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

    // The guest's manual trigger must be denied: the owner's current role no
    // longer authorizes running the workflow.
    let ok = member
        .send_event(workflow_trigger(&member_keys, &workflow_id))
        .await
        .expect("guest kind:46020 trigger");
    assert!(
        !ok.accepted,
        "guest-owned workflow trigger must be rejected after member→guest downgrade: {}",
        ok.message
    );

    // The critical assertion: no kind:9 produced by the workflow may land in
    // the channel, however the trigger door was denied.
    let pool = e2e_db_pool().await;
    let appeared = wait_for_channel_message(
        &pool,
        community_id,
        &channel_id,
        &marker,
        std::time::Duration::from_secs(5),
    )
    .await;
    assert!(
        !appeared,
        "a guest-owned workflow must not post a kind:9 into the channel"
    );

    owner.disconnect().await.expect("disconnect owner");
    member.disconnect().await.expect("disconnect member");
}

/// Positive control: a member-owned workflow still defines, triggers, and
/// posts its kind:9 — the guest fixes must not break legitimate workflows.
#[tokio::test]
#[ignore]
async fn test_member_workflow_still_posts_channel_message() {
    let url = relay_url();
    let community_id = ensure_test_community().await;
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

    let workflow_id = uuid::Uuid::new_v4().to_string();
    let marker = format!("member-wf-run-probe-{}", uuid::Uuid::new_v4());
    let mut member = buzz_test_client::BuzzTestClient::connect(&url, &member_keys)
        .await
        .expect("connect as member");
    let ok = member
        .send_event(workflow_def(
            &member_keys,
            &channel_id,
            &workflow_id,
            "member-def",
            &marker,
        ))
        .await
        .expect("member kind:30620 publish");
    assert!(
        ok.accepted,
        "member kind:30620 workflow definition must be accepted: {}",
        ok.message
    );

    let ok = member
        .send_event(workflow_trigger(&member_keys, &workflow_id))
        .await
        .expect("member kind:46020 trigger");
    assert!(
        ok.accepted,
        "member-owned workflow trigger must be accepted: {}",
        ok.message
    );

    // The workflow runs asynchronously; its kind:9 must land in the channel.
    let pool = e2e_db_pool().await;
    let appeared = wait_for_channel_message(
        &pool,
        community_id,
        &channel_id,
        &marker,
        std::time::Duration::from_secs(15),
    )
    .await;
    assert!(
        appeared,
        "member-owned workflow must post its kind:9 into the channel"
    );

    owner.disconnect().await.expect("disconnect owner");
    member.disconnect().await.expect("disconnect member");
}

/// Channel-scoped command events obey the shared gate: a guest's DM
/// add-member (kind:41011) is denied even where the legacy presence check
/// would have passed, while a member's DM add-member keeps working (DM
/// participants always hold the `member` role, so DM flows are unaffected).
#[tokio::test]
#[ignore]
async fn test_guest_channel_command_denied_member_dm_command_allowed() {
    let url = relay_url();
    ensure_test_community().await;
    let owner_keys = Keys::generate();
    let member_keys = Keys::generate();
    let guest_keys = Keys::generate();
    let third_keys = Keys::generate();

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
        &guest_keys.public_key().to_hex(),
        Some("guest"),
        &owner_keys,
    )
    .await;
    assert!(accepted, "owner should add guest, got: {msg}");

    // The member opens a DM with the owner and learns the DM channel id.
    let mut member = buzz_test_client::BuzzTestClient::connect(&url, &member_keys)
        .await
        .expect("connect as member");
    let ok = member
        .send_event(dm_open(&member_keys, &owner_keys.public_key().to_hex()))
        .await
        .expect("member kind:41010 DM open");
    assert!(
        ok.accepted,
        "member DM open must be accepted: {}",
        ok.message
    );
    let dm_channel_id = parse_response_channel_id(&ok.message, "DM open");

    // Guest's channel-scoped command is denied by the write gate — even
    // though the legacy handler would have seen an active membership row.
    let mut guest = buzz_test_client::BuzzTestClient::connect(&url, &guest_keys)
        .await
        .expect("connect as guest");
    let ok = guest
        .send_event(dm_add_member(
            &guest_keys,
            &channel_id,
            &third_keys.public_key().to_hex(),
        ))
        .await
        .expect("guest kind:41011 publish");
    assert!(
        !ok.accepted,
        "guest kind:41011 channel command must be rejected: {}",
        ok.message
    );
    assert!(
        ok.message.contains("guest") || ok.message.contains("read-only"),
        "rejection should name the guest read-only restriction, got: {}",
        ok.message
    );

    // Member's DM add-member still works: DM participants hold `member`.
    let ok = member
        .send_event(dm_add_member(
            &member_keys,
            &dm_channel_id,
            &third_keys.public_key().to_hex(),
        ))
        .await
        .expect("member kind:41011 publish");
    assert!(
        ok.accepted,
        "member kind:41011 DM add-member must be accepted: {}",
        ok.message
    );

    owner.disconnect().await.expect("disconnect owner");
    member.disconnect().await.expect("disconnect member");
    guest.disconnect().await.expect("disconnect guest");
}

/// A guest must not be able to join a huddle audio channel, even though it
/// holds an active channel membership row: speaking in a huddle is a channel
/// write, and the audio admission path must enforce the same read-only rule
/// as the event write gate (fresh role read at join time).
#[tokio::test]
#[ignore]
async fn test_guest_cannot_join_audio_huddle() {
    let url = relay_url();
    ensure_test_community().await;
    let owner_keys = Keys::generate();
    let guest_keys = Keys::generate();
    let member_keys = Keys::generate();

    let mut owner = buzz_test_client::BuzzTestClient::connect(&url, &owner_keys)
        .await
        .expect("connect as owner");
    let channel_id = create_channel_ws(&mut owner, &owner_keys, "private").await;

    for (keys, role) in [(&guest_keys, "guest"), (&member_keys, "member")] {
        let (accepted, msg) = put_user_ws(
            &mut owner,
            &channel_id,
            &keys.public_key().to_hex(),
            Some(role),
            &owner_keys,
        )
        .await;
        assert!(accepted, "owner should add {role}, got: {msg}");
    }

    let audio_url = format!("{}/huddle/{}/audio", url, channel_id);

    // Guest: completes NIP-42 auth, then must be refused at membership. The
    // refusal carries a distinct `reason` so a guest denial is distinguishable
    // from a generic refusal.
    let reply = huddle_handshake(&audio_url, &url, &guest_keys, None).await;
    let reply_json: serde_json::Value = serde_json::from_str(&reply).unwrap_or_default();
    assert_eq!(reply_json["type"], "error");
    assert!(
        reply_json["reason"]
            .as_str()
            .map(|r| r.contains("guest") || r.contains("read-only"))
            .unwrap_or(false),
        "guest audio join must be refused with a distinct guest reason, got: {reply}"
    );

    // Control: a member completing the same handshake is admitted (receives
    // the joined frame), so the guest refusal is not a blanket audio outage.
    let reply = huddle_handshake(&audio_url, &url, &member_keys, None).await;
    assert!(
        reply.contains("\"joined\""),
        "member audio join must proceed to joined, got: {reply}"
    );

    owner.disconnect().await.expect("disconnect owner");
}

/// Drive the huddle audio WebSocket handshake through NIP-42 auth and return
/// the first post-auth text frame: the error payload on refusal (with a
/// `reason` field for guest read-only denials), or the joined frame on
/// admission. `parent` is the claimed parent linkage for ephemeral huddles.
async fn huddle_handshake(
    audio_url: &str,
    relay_url: &str,
    keys: &Keys,
    parent: Option<uuid::Uuid>,
) -> String {
    use futures_util::{SinkExt, StreamExt};

    let (mut ws, _) = tokio_tungstenite::connect_async(audio_url)
        .await
        .expect("connect audio ws");
    let challenge_frame = ws
        .next()
        .await
        .expect("challenge frame")
        .expect("challenge ok");
    let challenge_json: serde_json::Value =
        serde_json::from_str(challenge_frame.to_text().expect("challenge text"))
            .expect("challenge json");
    assert_eq!(challenge_json["type"], "challenge");
    let challenge = challenge_json["challenge"]
        .as_str()
        .expect("challenge string")
        .to_string();

    let auth_event =
        buzz_ws_client::build_auth_event(&challenge, relay_url, keys, None).expect("auth event");
    let mut auth_msg =
        serde_json::json!({"type": "auth", "event": auth_event, "protocol_version": 1});
    if let Some(parent) = parent {
        auth_msg["parent_channel_id"] = serde_json::json!(parent.to_string());
    }
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        auth_msg.to_string().into(),
    ))
    .await
    .expect("send auth");

    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        while let Some(frame) = ws.next().await {
            let frame = frame.expect("post-auth frame");
            if let tokio_tungstenite::tungstenite::Message::Text(text) = frame {
                return text.to_string();
            }
        }
        panic!("audio socket closed without a post-auth text frame");
    })
    .await
    .expect("post-auth frame timeout")
}

/// Create a channel over WebSocket with explicit visibility/ttl tags and
/// return the channel UUID. `visibility: None` omits the tag — the create
/// path defaults to "open", which is how real ephemeral huddles are born.
async fn create_channel_custom_ws(
    client: &mut buzz_test_client::BuzzTestClient,
    keys: &Keys,
    visibility: Option<&str>,
    ttl: Option<&str>,
) -> String {
    let channel_uuid = uuid::Uuid::new_v4().to_string();
    let channel_name = format!("guest-denial-{}", channel_uuid);
    let mut tags = vec![
        Tag::parse(["h", &channel_uuid]).unwrap(),
        Tag::parse(["name", &channel_name]).unwrap(),
        Tag::parse(["channel_type", "stream"]).unwrap(),
    ];
    if let Some(visibility) = visibility {
        tags.push(Tag::parse(["visibility", visibility]).unwrap());
    }
    if let Some(ttl) = ttl {
        tags.push(Tag::parse(["ttl", ttl]).unwrap());
    }
    let event = EventBuilder::new(Kind::Custom(9007), "")
        .tags(tags)
        .sign_with_keys(keys)
        .unwrap();
    let ok = client.send_event(event).await.expect("create channel");
    assert!(ok.accepted, "channel creation failed: {}", ok.message);
    channel_uuid
}

/// Publish the creator-signed kind:48100 link that ties an ephemeral huddle
/// to its parent channel.
async fn start_huddle_link_ws(
    client: &mut buzz_test_client::BuzzTestClient,
    parent_channel_id: &str,
    huddle_channel_id: &str,
    signer: &Keys,
) {
    let content = serde_json::json!({"ephemeral_channel_id": huddle_channel_id}).to_string();
    let event = EventBuilder::new(Kind::Custom(48100), content)
        .tags(vec![Tag::parse(["h", parent_channel_id]).unwrap()])
        .sign_with_keys(signer)
        .unwrap();
    let ok = client.send_event(event).await.expect("send huddle start");
    assert!(ok.accepted, "huddle start link failed: {}", ok.message);
}

/// Sign a kind:5 (NIP-09) deletion of an addressable target via a tag.
fn nip09_a_tag_delete(keys: &Keys, a_tag: &str) -> Event {
    EventBuilder::new(Kind::Custom(5), "")
        .tags(vec![Tag::parse(["a", a_tag]).unwrap()])
        .sign_with_keys(keys)
        .unwrap()
}

/// Sign a kind:5 (NIP-09) deletion of a regular event via e tag.
fn nip09_e_tag_delete(keys: &Keys, target_id: &str) -> Event {
    EventBuilder::new(Kind::Custom(5), "")
        .tags(vec![Tag::parse(["e", target_id]).unwrap()])
        .sign_with_keys(keys)
        .unwrap()
}

/// A guest of the PARENT channel must not be able to speak in that channel's
/// ephemeral huddles: admission derives from the parent (the auto-add path
/// inserts parent members as full members, and an ephemeral channel without
/// an explicit visibility tag defaults to open), so the guest probe must run
/// against the parent too before any admission path can fire.
#[tokio::test]
#[ignore]
async fn test_guest_cannot_join_ephemeral_huddle_as_parent_guest() {
    let url = relay_url();
    ensure_test_community().await;
    let owner_keys = Keys::generate();
    let guest_keys = Keys::generate();
    let member_keys = Keys::generate();

    let mut owner = buzz_test_client::BuzzTestClient::connect(&url, &owner_keys)
        .await
        .expect("connect as owner");
    let parent_id = create_channel_ws(&mut owner, &owner_keys, "private").await;

    for (keys, role) in [(&guest_keys, "guest"), (&member_keys, "member")] {
        let (accepted, msg) = put_user_ws(
            &mut owner,
            &parent_id,
            &keys.public_key().to_hex(),
            Some(role),
            &owner_keys,
        )
        .await;
        assert!(accepted, "owner should add {role} to parent, got: {msg}");
    }

    // Ephemeral huddle with NO visibility tag — defaults to open, the
    // fallback-admission case.
    let open_huddle = create_channel_custom_ws(&mut owner, &owner_keys, None, Some("600")).await;
    start_huddle_link_ws(&mut owner, &parent_id, &open_huddle, &owner_keys).await;

    // Ephemeral huddle explicitly private — the auto-add case.
    let private_huddle =
        create_channel_custom_ws(&mut owner, &owner_keys, Some("private"), Some("600")).await;
    start_huddle_link_ws(&mut owner, &parent_id, &private_huddle, &owner_keys).await;

    let parent_uuid = uuid::Uuid::parse_str(&parent_id).unwrap();

    for huddle in [&open_huddle, &private_huddle] {
        let audio_url = format!("{}/huddle/{}/audio", url, huddle);
        let reply = huddle_handshake(&audio_url, &url, &guest_keys, Some(parent_uuid)).await;
        let reply_json: serde_json::Value = serde_json::from_str(&reply).unwrap_or_default();
        assert_eq!(
            reply_json["type"], "error",
            "parent guest must be refused for huddle {huddle}: {reply}"
        );
        assert!(
            reply_json["reason"]
                .as_str()
                .map(|r| r.contains("guest") || r.contains("read-only"))
                .unwrap_or(false),
            "parent guest refusal must name the guest read-only restriction, got: {reply}"
        );
    }

    // Control: a parent member is admitted to the private huddle via the
    // auto-add path — the parent probe must not over-deny.
    let audio_url = format!("{}/huddle/{}/audio", url, private_huddle);
    let reply = huddle_handshake(&audio_url, &url, &member_keys, Some(parent_uuid)).await;
    assert!(
        reply.contains("\"joined\""),
        "parent member must be auto-admitted to the private huddle, got: {reply}"
    );

    owner.disconnect().await.expect("disconnect owner");
}

/// A guest owning an owner-role agent must not be able to NIP-09 (kind:5)
/// delete the agent's channel-scoped addressable events: kind:5 is not
/// h-scoped, so a-tag deletions never pass the generic write gate and the
/// ownership fallback must not lift the guest read-only restriction.
#[tokio::test]
#[ignore]
async fn test_guest_cannot_delete_agent_workflow_definition() {
    let url = relay_url();
    let community_id = ensure_test_community().await;
    let owner_keys = Keys::generate();
    let agent_keys = Keys::generate();
    let guest_keys = Keys::generate();

    let mut owner = buzz_test_client::BuzzTestClient::connect(&url, &owner_keys)
        .await
        .expect("connect as owner");
    // Open channel: the agent (a non-member) can define a workflow in it.
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

    let pool = e2e_db_pool().await;
    seed_agent_owner(&pool, community_id, &agent_keys, &guest_keys).await;

    let mut agent = buzz_test_client::BuzzTestClient::connect(&url, &agent_keys)
        .await
        .expect("connect as agent");
    let workflow_id = uuid::Uuid::new_v4().to_string();
    let ok = agent
        .send_event(workflow_def(
            &agent_keys,
            &channel_id,
            &workflow_id,
            "agent-def",
            "agent-def-marker",
        ))
        .await
        .expect("agent kind:30620 publish");
    assert!(
        ok.accepted,
        "agent workflow definition must be accepted: {}",
        ok.message
    );

    let a_tag = format!("30620:{}:{workflow_id}", agent_keys.public_key().to_hex());
    let mut guest = buzz_test_client::BuzzTestClient::connect(&url, &guest_keys)
        .await
        .expect("connect as guest");
    let ok = guest
        .send_event(nip09_a_tag_delete(&guest_keys, &a_tag))
        .await
        .expect("guest kind:5 a-tag publish");
    assert!(
        !ok.accepted,
        "guest must not delete the agent's workflow definition via kind:5, but it was accepted: {}",
        ok.message
    );
    assert!(
        ok.message.contains("guest") || ok.message.contains("read-only"),
        "rejection should name the guest read-only restriction, got: {}",
        ok.message
    );

    // Control: the agent deleting its own definition stays allowed.
    let ok = agent
        .send_event(nip09_a_tag_delete(&agent_keys, &a_tag))
        .await
        .expect("agent kind:5 a-tag publish");
    assert!(
        ok.accepted,
        "agent self-delete of its definition must be accepted: {}",
        ok.message
    );

    owner.disconnect().await.expect("disconnect owner");
    agent.disconnect().await.expect("disconnect agent");
    guest.disconnect().await.expect("disconnect guest");
}

/// A member downgraded to guest must not be able to kind:5-delete its own
/// pre-downgrade addressable events: the author self-deletion re-gates the
/// current role through the shared write gate, mirroring kind:9005.
#[tokio::test]
#[ignore]
async fn test_downgraded_guest_cannot_delete_own_addressable_event() {
    let url = relay_url();
    ensure_test_community().await;
    let owner_keys = Keys::generate();
    let member_keys = Keys::generate();

    let mut owner = buzz_test_client::BuzzTestClient::connect(&url, &owner_keys)
        .await
        .expect("connect as owner");
    let channel_id = create_channel_ws(&mut owner, &owner_keys, "open").await;

    let (accepted, msg) = put_user_ws(
        &mut owner,
        &channel_id,
        &member_keys.public_key().to_hex(),
        Some("member"),
        &owner_keys,
    )
    .await;
    assert!(accepted, "owner should add member, got: {msg}");

    let mut member = buzz_test_client::BuzzTestClient::connect(&url, &member_keys)
        .await
        .expect("connect as member");
    let control_def = uuid::Uuid::new_v4().to_string();
    let probe_def = uuid::Uuid::new_v4().to_string();
    for (wf, name) in [(&control_def, "control-def"), (&probe_def, "probe-def")] {
        let ok = member
            .send_event(workflow_def(
                &member_keys,
                &channel_id,
                wf,
                name,
                &format!("{name}-marker"),
            ))
            .await
            .expect("member kind:30620 publish");
        assert!(
            ok.accepted,
            "member workflow definition must be accepted: {}",
            ok.message
        );
    }

    // Control: a member can still kind:5-delete its own addressable event.
    let control_tag = format!("30620:{}:{control_def}", member_keys.public_key().to_hex());
    let ok = member
        .send_event(nip09_a_tag_delete(&member_keys, &control_tag))
        .await
        .expect("member kind:5 a-tag publish");
    assert!(
        ok.accepted,
        "member self-delete must be accepted: {}",
        ok.message
    );

    // Downgrade, then the same self-delete must be refused.
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

    let probe_tag = format!("30620:{}:{probe_def}", member_keys.public_key().to_hex());
    let ok = member
        .send_event(nip09_a_tag_delete(&member_keys, &probe_tag))
        .await
        .expect("downgraded kind:5 a-tag publish");
    assert!(
        !ok.accepted,
        "downgraded guest must not delete its own pre-downgrade addressable event, but it was accepted: {}",
        ok.message
    );
    assert!(
        ok.message.contains("guest") || ok.message.contains("read-only"),
        "rejection should name the guest read-only restriction, got: {}",
        ok.message
    );

    owner.disconnect().await.expect("disconnect owner");
    member.disconnect().await.expect("disconnect member");
}

/// A guest owning an agent must not be able to kind:5-delete the agent's
/// channel-scoped messages: the write gate derives the target's channel for
/// e-tag deletions and denies the guest identity.
#[tokio::test]
#[ignore]
async fn test_guest_cannot_delete_agents_message_kind5() {
    let url = relay_url();
    let community_id = ensure_test_community().await;
    let owner_keys = Keys::generate();
    let agent_keys = Keys::generate();
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

    let pool = e2e_db_pool().await;
    seed_agent_owner(&pool, community_id, &agent_keys, &guest_keys).await;

    let mut agent = buzz_test_client::BuzzTestClient::connect(&url, &agent_keys)
        .await
        .expect("connect as agent");
    let ok = agent
        .send_event(stream_message(&agent_keys, &channel_id, "agent message"))
        .await
        .expect("agent kind:9 publish");
    assert!(ok.accepted, "agent kind:9 must be accepted: {}", ok.message);

    let mut guest = buzz_test_client::BuzzTestClient::connect(&url, &guest_keys)
        .await
        .expect("connect as guest");
    let ok = guest
        .send_event(nip09_e_tag_delete(&guest_keys, &ok.event_id))
        .await
        .expect("guest kind:5 e-tag publish");
    assert!(
        !ok.accepted,
        "guest must not delete the agent's message via kind:5, but it was accepted: {}",
        ok.message
    );
    assert!(
        ok.message.contains("guest") || ok.message.contains("read-only"),
        "rejection should name the guest read-only restriction, got: {}",
        ok.message
    );

    owner.disconnect().await.expect("disconnect owner");
    agent.disconnect().await.expect("disconnect agent");
    guest.disconnect().await.expect("disconnect guest");
}
