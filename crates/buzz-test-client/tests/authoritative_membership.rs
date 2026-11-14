//! Launches the actual relay binary against disposable PostgreSQL and Redis.
//! Build buzz-relay first; all infrastructure settings must be explicit.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use buzz_test_client::BuzzTestClient;
use futures_util::{SinkExt, StreamExt};
use nostr::{Event, EventBuilder, JsonUtil, Keys, Kind, Tag};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};
use uuid::Uuid;

type AudioSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn audio_connect(channel: Uuid, keys: &Keys) -> AudioSocket {
    use tokio_tungstenite::tungstenite::Message;
    let (mut socket, _) =
        tokio_tungstenite::connect_async(format!("ws://localhost:55443/huddle/{channel}/audio"))
            .await
            .unwrap();
    let challenge = tokio::time::timeout(Duration::from_secs(3), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let challenge: Value = serde_json::from_str(challenge.to_text().unwrap()).unwrap();
    let event = EventBuilder::new(Kind::Custom(22242), "")
        .tags([
            Tag::parse(["relay", "ws://localhost:55443"]).unwrap(),
            Tag::parse(["challenge", challenge["challenge"].as_str().unwrap()]).unwrap(),
        ])
        .sign_with_keys(keys)
        .unwrap();
    socket
        .send(Message::Text(
            json!({"type":"auth","event":event}).to_string().into(),
        ))
        .await
        .unwrap();
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(3), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let Message::Text(text) = msg {
            let msg: Value = serde_json::from_str(&text).unwrap();
            assert_ne!(msg["type"], "error", "audio admission failed: {msg}");
            if msg["type"] == "joined" && msg["pubkey"] == keys.public_key().to_hex() {
                return socket;
            }
        }
    }
}

async fn audio_rejected(channel: Uuid, keys: &Keys) -> bool {
    use tokio_tungstenite::tungstenite::Message;
    let Ok((mut socket, _)) =
        tokio_tungstenite::connect_async(format!("ws://localhost:55443/huddle/{channel}/audio"))
            .await
    else {
        return true;
    };
    let Ok(Some(Ok(challenge))) = tokio::time::timeout(Duration::from_secs(3), socket.next()).await
    else {
        return true;
    };
    let Ok(challenge) = serde_json::from_str::<Value>(challenge.to_text().unwrap_or_default())
    else {
        return true;
    };
    let Ok(event) = EventBuilder::new(Kind::Custom(22242), "")
        .tags([
            Tag::parse(["relay", "ws://localhost:55443"]).unwrap(),
            Tag::parse([
                "challenge",
                challenge["challenge"].as_str().unwrap_or_default(),
            ])
            .unwrap(),
        ])
        .sign_with_keys(keys)
    else {
        return false;
    };
    if socket
        .send(Message::Text(
            json!({"type":"auth","event":event}).to_string().into(),
        ))
        .await
        .is_err()
    {
        return true;
    }
    matches!(
        tokio::time::timeout(Duration::from_secs(3), socket.next()).await,
        Ok(Some(Ok(Message::Text(text)))) if serde_json::from_str::<Value>(&text)
            .is_ok_and(|message| message["type"] == "error")
    )
}

async fn assert_audio_closed(socket: &mut AudioSocket) {
    use tokio_tungstenite::tungstenite::Message;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match tokio::time::timeout_at(deadline, socket.next())
            .await
            .unwrap()
        {
            None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
            Some(Ok(Message::Binary(_))) => panic!("revoked audio peer received media"),
            _ => {}
        }
    }
}

struct Relay(Child);
impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn launch(service: &Keys, relay: Option<&Keys>, database_url: &str, closed: bool) -> Relay {
    let log = std::fs::File::create(std::env::temp_dir().join("membership-conformance-relay.log"))
        .unwrap();
    let mut command =
        Command::new(std::env::var("BUZZ_TEST_RELAY_BINARY").expect("build buzz-relay first"));
    if let Some(relay) = relay {
        command.env("BUZZ_RELAY_PRIVATE_KEY", relay.secret_key().to_secret_hex());
    } else {
        command.env_remove("BUZZ_RELAY_PRIVATE_KEY");
    }
    Relay(
        command
            .env("DATABASE_URL", database_url)
            .env("REDIS_URL", std::env::var("BUZZ_TEST_REDIS_URL").unwrap())
            .env("RELAY_URL", "ws://localhost:55443")
            .env("BUZZ_BIND_ADDR", "127.0.0.1:55443")
            .env("BUZZ_HEALTH_PORT", "55444")
            .env("BUZZ_METRICS_PORT", "55445")
            .env("BUZZ_AUTO_MIGRATE", "true")
            .env("BUZZ_GIT_ENABLED", "false")
            .env("RELAY_OWNER_PUBKEY", service.public_key().to_hex())
            .env(
                "RELAY_TRUSTED_SERVICE_PUBKEYS",
                service.public_key().to_hex(),
            )
            .env("BUZZ_REQUIRE_AUTH_TOKEN", relay.is_some().to_string())
            .env("BUZZ_REQUIRE_RELAY_MEMBERSHIP", closed.to_string())
            .env("BUZZ_ALLOW_NIP_OA_AUTH", "true")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    )
}

async fn ready(http: &reqwest::Client) {
    for _ in 0..120 {
        if http
            .get("http://localhost:55443/health")
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("relay did not become ready; inspect membership-conformance-relay.log");
}

fn auth(keys: &Keys, host: &str, path: &str, body: &[u8]) -> String {
    let tags = [
        vec!["u".into(), format!("http://{host}{path}")],
        vec!["method".into(), "POST".into()],
        vec!["payload".into(), hex::encode(Sha256::digest(body))],
        vec!["nonce".into(), Uuid::new_v4().to_string()],
    ]
    .into_iter()
    .map(|t| Tag::parse(t).unwrap());
    let event = EventBuilder::new(Kind::HttpAuth, "")
        .tags(tags)
        .sign_with_keys(keys)
        .unwrap();
    format!("Nostr {}", STANDARD.encode(event.as_json()))
}

async fn post(
    http: &reqwest::Client,
    keys: &Keys,
    host: &str,
    path: &str,
    body: &Value,
) -> reqwest::Response {
    let body = serde_json::to_vec(body).unwrap();
    http.post(format!("http://localhost:55443{path}"))
        .header("Host", host)
        .header("Authorization", auth(keys, host, path, &body))
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap()
}

async fn read(http: &reqwest::Client, service: &Keys, relay: &Keys, c: Uuid, p: &str) -> Value {
    let request = json!({"request_id":Uuid::new_v4(),"community_id":c,"pubkey":p});
    let response = post(
        http,
        service,
        "localhost:55443",
        "/api/v1/relay/membership/check",
        &request,
    )
    .await;
    assert_eq!(response.status(), 200);
    let event = Event::from_json(response.text().await.unwrap()).unwrap();
    event.verify().unwrap();
    assert_eq!(event.pubkey, relay.public_key());
    assert_eq!(event.kind.as_u16(), 19030);
    let content: Value = serde_json::from_str(&event.content).unwrap();
    for field in ["request_id", "community_id", "pubkey"] {
        assert_eq!(content[field], request[field]);
    }
    assert!(
        content["evaluated_at"]
            .as_u64()
            .unwrap()
            .abs_diff(nostr::Timestamp::now().as_secs())
            <= 5
    );
    content
}

async fn mutate(
    http: &reqwest::Client,
    actor: &Keys,
    p: &str,
    kind: u16,
    op: Uuid,
    revision: u64,
) -> bool {
    mutate_with_extra_tags(http, actor, p, kind, op, revision, Vec::new()).await
}

async fn mutate_with_extra_tags(
    http: &reqwest::Client,
    actor: &Keys,
    p: &str,
    kind: u16,
    op: Uuid,
    revision: u64,
    extra_tags: Vec<Vec<String>>,
) -> bool {
    let mut tags = vec![
        vec!["p".into(), p.into()],
        vec!["elembra-op".into(), op.to_string()],
        vec!["elembra-expected-revision".into(), revision.to_string()],
    ];
    tags.extend(extra_tags);
    let tags = tags.into_iter().map(|t| Tag::parse(t).unwrap());
    let event = EventBuilder::new(Kind::Custom(kind), "")
        .tags(tags)
        .sign_with_keys(actor)
        .unwrap();
    let response = post(
        http,
        actor,
        "localhost:55443",
        "/events",
        &serde_json::to_value(event).unwrap(),
    )
    .await;
    let status = response.status();
    let result: Value = response.json().await.unwrap();
    status.is_success() && result["accepted"].as_bool().unwrap_or(false)
}

async fn assert_revoked_admission(http: &reqwest::Client, owner: &Keys, revoked: &Keys) {
    let delegation =
        buzz_sdk::nip_oa::compute_auth_tag(owner, &revoked.public_key(), "kind=0").unwrap();
    let tag = buzz_sdk::nip_oa::parse_auth_tag(&delegation).unwrap();
    let mut session = BuzzTestClient::connect_unauthenticated("ws://localhost:55443")
        .await
        .unwrap();
    assert!(session
        .authenticate_with_nip_oa(revoked, &tag)
        .await
        .is_err());
    let event = EventBuilder::new(Kind::Metadata, "{}")
        .sign_with_keys(revoked)
        .unwrap();
    let bytes = serde_json::to_vec(&event).unwrap();
    let response = http
        .post("http://localhost:55443/events")
        .header(
            "Authorization",
            auth(revoked, "localhost:55443", "/events", &bytes),
        )
        .header("x-auth-tag", delegation)
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(
        BuzzTestClient::connect("ws://localhost:55443", &Keys::generate())
            .await
            .is_err()
    );
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL/Redis, Docker, and built relay binary"]
async fn live_membership_contract() {
    let mut database_url =
        url::Url::parse(&std::env::var("BUZZ_TEST_DATABASE_URL").unwrap()).unwrap();
    assert!(
        database_url.query().is_none(),
        "test database URL must not redirect through connection parameters"
    );
    assert!(matches!(
        database_url.host_str(),
        Some("127.0.0.1" | "localhost")
    ));
    let admin = PgPool::connect(database_url.as_str()).await.unwrap();
    let name = format!("membership_live_{}", Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&admin)
        .await
        .unwrap();
    database_url.set_path(&name);
    let service = Keys::generate();
    let relay = Keys::generate();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let mut process = launch(&service, Some(&relay), database_url.as_str(), false);
    ready(&http).await;
    let pool = PgPool::connect(database_url.as_str()).await.unwrap();
    let c: Uuid = sqlx::query_scalar("SELECT id FROM communities WHERE host='localhost:55443'")
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE communities SET membership_v1alpha2=true WHERE id=$1")
        .bind(c)
        .execute(&pool)
        .await
        .unwrap();
    let member = Keys::generate();
    let p = member.public_key().to_hex();
    let initial = read(&http, &service, &relay, c, &p).await;
    assert_eq!(initial["membership"], "absent");
    assert_eq!(initial["membership_revision"], 0);
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE relay_members IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let delayed = tokio::spawn({
        let (http, service, relay, p) = (http.clone(), service.clone(), relay.clone(), p.clone());
        async move { read(&http, &service, &relay, c, &p).await }
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let waiting: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' \
             AND query LIKE '%s.revision, s.revoked%')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        if waiting {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "membership read did not wait on lock"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let waited_at = nostr::Timestamp::now().as_secs();
    while nostr::Timestamp::now().as_secs() <= waited_at {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let released_at = nostr::Timestamp::now().as_secs();
    blocker.commit().await.unwrap();
    assert!(delayed.await.unwrap()["evaluated_at"].as_u64().unwrap() < released_at);
    let op = Uuid::new_v4();
    assert!(mutate(&http, &service, &p, 9030, op, 0).await);
    assert!(mutate(&http, &service, &p, 9030, op, 0).await);
    let active = read(&http, &service, &relay, c, &p).await;
    assert_eq!(active["membership"], "active");
    assert_eq!(active["membership_revision"], 1);
    assert!(mutate(&http, &service, &p, 9030, Uuid::new_v4(), 1).await);
    assert_eq!(
        read(&http, &service, &relay, c, &p).await["membership_revision"],
        1
    );
    assert!(!mutate(&http, &service, &p, 9031, op, 1).await);
    assert!(!mutate(&http, &service, &p, 9031, Uuid::new_v4(), 0).await);
    assert!(!mutate(&http, &Keys::generate(), &p, 9031, Uuid::new_v4(), 1).await);
    let audio_channel = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO channels (community_id,id,name,created_by) VALUES ($1,$2,'audio-test',$3)",
    )
    .bind(c)
    .bind(audio_channel)
    .bind(service.public_key().to_bytes().to_vec())
    .execute(&pool)
    .await
    .unwrap();
    // v1alpha2 must enforce exact-key admission even on this open relay.
    let mut publisher = BuzzTestClient::connect("ws://localhost:55443", &service)
        .await
        .unwrap();
    let visible_event = EventBuilder::new(Kind::Custom(20002), "visible to members")
        .sign_with_keys(&service)
        .unwrap();
    assert!(publisher.send_event(visible_event).await.unwrap().accepted);
    drop(publisher);
    let staged = Keys::generate();
    let staged_pubkey = staged.public_key().to_hex();
    let staged_op = Uuid::new_v4();
    assert!(
        !mutate_with_extra_tags(
            &http,
            &Keys::generate(),
            &staged_pubkey,
            9030,
            staged_op,
            0,
            vec![vec!["elembra-stage".into(), "true".into()]],
        )
        .await
    );
    assert!(
        mutate_with_extra_tags(
            &http,
            &service,
            &staged_pubkey,
            9030,
            staged_op,
            0,
            vec![vec!["elembra-stage".into(), "true".into()]],
        )
        .await
    );
    let staged_state = read(&http, &service, &relay, c, &staged_pubkey).await;
    assert_eq!(staged_state["membership"], "active");
    assert_eq!(staged_state["membership_revision"], 1);
    assert_eq!(staged_state["send_enabled"], false);
    assert_eq!(staged_state["staged_operation_id"], staged_op.to_string());
    assert!(BuzzTestClient::connect("ws://localhost:55443", &staged)
        .await
        .is_err());
    let delegation =
        buzz_sdk::nip_oa::compute_auth_tag(&service, &staged.public_key(), "kind=0").unwrap();
    let delegation = buzz_sdk::nip_oa::parse_auth_tag(&delegation).unwrap();
    let mut delegated = BuzzTestClient::connect_unauthenticated("ws://localhost:55443")
        .await
        .unwrap();
    assert!(delegated
        .authenticate_with_nip_oa(&staged, &delegation)
        .await
        .is_err());
    let event = EventBuilder::new(Kind::Metadata, "{}")
        .sign_with_keys(&staged)
        .unwrap();
    let response = post(
        &http,
        &staged,
        "localhost:55443",
        "/events",
        &serde_json::to_value(event.clone()).unwrap(),
    )
    .await;
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    let body = serde_json::to_vec(&serde_json::to_value(event).unwrap()).unwrap();
    let response = http
        .post("http://localhost:55443/events")
        .header("Host", "localhost:55443")
        .header(
            "Authorization",
            auth(&staged, "localhost:55443", "/events", &body),
        )
        .header(
            "x-auth-tag",
            buzz_sdk::nip_oa::compute_auth_tag(&service, &staged.public_key(), "kind=0").unwrap(),
        )
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(audio_rejected(audio_channel, &staged).await);
    let mut unauthenticated = BuzzTestClient::connect_unauthenticated("ws://localhost:55443")
        .await
        .unwrap();
    let event = EventBuilder::new(Kind::Metadata, "{}")
        .sign_with_keys(&staged)
        .unwrap();
    assert!(!unauthenticated
        .send_event(event)
        .await
        .is_ok_and(|response| response.accepted));
    unauthenticated
        .subscribe(
            "staged-open-relay",
            vec![nostr::Filter::new().kind(Kind::Custom(20002))],
        )
        .await
        .unwrap();
    assert!(!matches!(
        unauthenticated.recv_event(Duration::from_millis(300)).await,
        Ok(buzz_test_client::RelayMessage::Event { .. })
    ));

    let stale_release = Uuid::new_v4();
    assert!(
        !mutate_with_extra_tags(
            &http,
            &service,
            &staged_pubkey,
            9030,
            stale_release,
            0,
            vec![vec!["elembra-release-of".into(), staged_op.to_string()]],
        )
        .await
    );
    let release_op = Uuid::new_v4();
    assert!(
        !mutate_with_extra_tags(
            &http,
            &Keys::generate(),
            &staged_pubkey,
            9030,
            release_op,
            1,
            vec![vec!["elembra-release-of".into(), staged_op.to_string()]],
        )
        .await
    );
    let release_tags = vec![vec!["elembra-release-of".into(), staged_op.to_string()]];
    assert!(
        mutate_with_extra_tags(
            &http,
            &service,
            &staged_pubkey,
            9030,
            release_op,
            1,
            release_tags.clone(),
        )
        .await
    );
    assert!(
        mutate_with_extra_tags(
            &http,
            &service,
            &staged_pubkey,
            9030,
            release_op,
            1,
            release_tags,
        )
        .await
    );
    let released_state = read(&http, &service, &relay, c, &staged_pubkey).await;
    assert_eq!(released_state["membership_revision"], 2);
    assert_eq!(released_state["send_enabled"], true);
    assert_eq!(released_state["staged_operation_id"], Value::Null);

    let revoked_staged = Keys::generate();
    let revoked_op = Uuid::new_v4();
    assert!(
        mutate_with_extra_tags(
            &http,
            &service,
            &revoked_staged.public_key().to_hex(),
            9030,
            revoked_op,
            0,
            vec![vec!["elembra-stage".into(), "true".into()]],
        )
        .await
    );
    let revoked_staged_pubkey = revoked_staged.public_key().to_hex();
    assert!(
        mutate(
            &http,
            &service,
            &revoked_staged_pubkey,
            9031,
            Uuid::new_v4(),
            1
        )
        .await
    );
    assert!(
        !mutate_with_extra_tags(
            &http,
            &service,
            &revoked_staged_pubkey,
            9030,
            Uuid::new_v4(),
            2,
            vec![vec!["elembra-release-of".into(), revoked_op.to_string()]],
        )
        .await
    );
    let revoked_state = read(&http, &service, &relay, c, &revoked_staged_pubkey).await;
    assert_eq!(revoked_state["membership"], "revoked");
    assert_eq!(revoked_state["send_enabled"], false);

    let mut audio_sender = audio_connect(audio_channel, &member).await;
    let mut audio_reader = audio_connect(audio_channel, &member).await;
    let mut audio_publisher = audio_connect(audio_channel, &service).await;
    use tokio_tungstenite::tungstenite::Message;
    audio_sender
        .send(Message::Binary(vec![7, 8, 9].into()))
        .await
        .unwrap();
    for audio in [&mut audio_publisher, &mut audio_reader] {
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(3), audio.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            if let Message::Binary(bytes) = frame {
                assert!(bytes.ends_with(&[7, 8, 9]));
                break;
            }
        }
    }
    let mut session = BuzzTestClient::connect("ws://localhost:55443", &member)
        .await
        .unwrap();
    let presence = EventBuilder::new(Kind::Custom(20001), "online")
        .sign_with_keys(&member)
        .unwrap();
    assert!(session.send_event(presence).await.unwrap().accepted);
    let mut reader = BuzzTestClient::connect("ws://localhost:55443", &member)
        .await
        .unwrap();
    reader
        .subscribe("live", vec![nostr::Filter::new().kind(Kind::Custom(20001))])
        .await
        .unwrap();
    reader
        .collect_until_eose("live", Duration::from_secs(3))
        .await
        .unwrap();
    assert!(mutate(&http, &service, &p, 9031, Uuid::new_v4(), 1).await);
    audio_sender
        .send(Message::Binary(vec![1, 2, 3].into()))
        .await
        .unwrap();
    assert_audio_closed(&mut audio_sender).await;
    audio_publisher
        .send(Message::Binary(vec![4, 5, 6].into()))
        .await
        .unwrap();
    assert_audio_closed(&mut audio_reader).await;
    drop((audio_sender, audio_reader, audio_publisher));
    let presence = EventBuilder::new(Kind::Custom(20001), "offline")
        .sign_with_keys(&member)
        .unwrap();
    assert!(!session.send_event(presence).await.unwrap().accepted);
    let mut publisher = BuzzTestClient::connect("ws://localhost:55443", &service)
        .await
        .unwrap();
    let mut witness = BuzzTestClient::connect("ws://localhost:55443", &service)
        .await
        .unwrap();
    witness
        .subscribe(
            "witness",
            vec![nostr::Filter::new().kind(Kind::Custom(20001))],
        )
        .await
        .unwrap();
    witness
        .collect_until_eose("witness", Duration::from_secs(3))
        .await
        .unwrap();
    let presence = EventBuilder::new(Kind::Custom(20001), "online")
        .sign_with_keys(&service)
        .unwrap();
    let presence_id = presence.id;
    assert!(publisher.send_event(presence).await.unwrap().accepted);
    assert!(
        matches!(witness.recv_event(Duration::from_secs(3)).await.unwrap(),
        buzz_test_client::RelayMessage::Event { event, .. } if event.id == presence_id)
    );
    assert!(matches!(
        reader.recv_event(Duration::from_millis(300)).await,
        Err(buzz_test_client::TestClientError::Timeout)
    ));
    drop((session, reader, publisher, witness));
    assert_revoked_admission(&http, &service, &member).await;
    let removed = read(&http, &service, &relay, c, &p).await;
    assert_eq!(removed["membership"], "revoked");
    assert_eq!(removed["membership_revision"], 2);
    assert!(!mutate(&http, &service, &p, 9030, Uuid::new_v4(), 2).await);
    assert!(!mutate(&http, &service, &p, 9030, Uuid::new_v4(), 0).await);
    let legacy = EventBuilder::new(Kind::Custom(9030), "")
        .tags([Tag::parse(["p", &p]).unwrap()])
        .sign_with_keys(&service)
        .unwrap();
    let response = post(
        &http,
        &service,
        "localhost:55443",
        "/events",
        &serde_json::to_value(legacy).unwrap(),
    )
    .await;
    assert!(!response.status().is_success());
    // New nonce, foreign community and untrusted auth must fail.
    let request = json!({"request_id":Uuid::new_v4(),"community_id":Uuid::new_v4(),"pubkey":p});
    assert_eq!(
        post(
            &http,
            &service,
            "localhost:55443",
            "/api/v1/relay/membership/check",
            &request
        )
        .await
        .status(),
        404
    );
    assert_eq!(
        post(
            &http,
            &Keys::generate(),
            "localhost:55443",
            "/api/v1/relay/membership/check",
            &request
        )
        .await
        .status(),
        401
    );
    assert_eq!(
        http.post("http://localhost:55443/api/v1/relay/membership/check")
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let mut invalid = request.clone();
    invalid["pubkey"] = json!("malformed");
    assert_eq!(
        post(
            &http,
            &service,
            "localhost:55443",
            "/api/v1/relay/membership/check",
            &invalid
        )
        .await
        .status(),
        400
    );

    // Real cryptographic auth failures: payload tampering and exact auth replay.
    let valid = json!({"request_id":Uuid::new_v4(),"community_id":c,"pubkey":p});
    let bytes = serde_json::to_vec(&valid).unwrap();
    let header = auth(
        &service,
        "localhost:55443",
        "/api/v1/relay/membership/check",
        &bytes,
    );
    let path = "http://localhost:55443/api/v1/relay/membership/check";
    assert_eq!(
        http.post(path)
            .header("Authorization", &header)
            .body("{}")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        http.post(path)
            .header("Authorization", &header)
            .body(bytes.clone())
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        http.post(path)
            .header("Authorization", &header)
            .body(bytes)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );

    // Same key, different authoritative community: never borrow the first roster.
    let other = Uuid::new_v4();
    sqlx::query("INSERT INTO communities (id,host,membership_v1alpha2) VALUES ($1,'other-membership.test:55443',true)")
        .bind(other).execute(&pool).await.unwrap();
    let isolated = json!({"request_id":Uuid::new_v4(),"community_id":other,"pubkey":p});
    let response = post(
        &http,
        &service,
        "other-membership.test:55443",
        "/api/v1/relay/membership/check",
        &isolated,
    )
    .await;
    assert_eq!(response.status(), 200);
    let event = Event::from_json(response.text().await.unwrap()).unwrap();
    event.verify().unwrap();
    let content: Value = serde_json::from_str(&event.content).unwrap();
    assert_eq!(content["membership"], "absent");
    assert_eq!(content["community_id"], other.to_string());
    // Two conditional first writes, same revision: exactly one can win.
    let racing = Keys::generate().public_key().to_hex();
    let (a, b) = tokio::join!(
        mutate(&http, &service, &racing, 9030, Uuid::new_v4(), 0),
        mutate(&http, &service, &racing, 9031, Uuid::new_v4(), 0)
    );
    assert_ne!(a, b);
    assert_eq!(
        read(&http, &service, &relay, c, &racing).await["membership_revision"],
        1
    );
    // Reads must leave all authoritative tables and receipts untouched.
    let snapshot = "SELECT jsonb_build_array( \
        (SELECT jsonb_agg(to_jsonb(m) ORDER BY community_id,pubkey) FROM relay_members m), \
        (SELECT jsonb_agg(to_jsonb(s) ORDER BY community_id,pubkey) FROM relay_membership_state s), \
        (SELECT jsonb_agg(to_jsonb(r) ORDER BY operation_id) FROM relay_membership_receipts r))";
    let before: Value = sqlx::query_scalar(snapshot).fetch_one(&pool).await.unwrap();
    read(
        &http,
        &service,
        &relay,
        c,
        &Keys::generate().public_key().to_hex(),
    )
    .await;
    let after: Value = sqlx::query_scalar(snapshot).fetch_one(&pool).await.unwrap();
    assert_eq!(before, after);
    drop(process);
    process = launch(&service, Some(&relay), database_url.as_str(), true);
    ready(&http).await;
    assert_revoked_admission(&http, &service, &member).await;
    ready(&http).await;
    assert_eq!(
        read(&http, &service, &relay, c, &p).await["membership_revision"],
        2
    );
    assert!(mutate(&http, &service, &p, 9030, op, 0).await); // Stored original receipt, not re-admission.
    assert_eq!(
        read(&http, &service, &relay, c, &p).await["membership"],
        "revoked"
    );
    // Pause only the explicitly named disposable test database container.
    let container =
        std::env::var("BUZZ_TEST_POSTGRES_CONTAINER").expect("disposable outage target required");
    assert!(container.starts_with("m41-buzz-"));
    assert!(Command::new("docker")
        .args(["pause", &container])
        .status()
        .unwrap()
        .success());
    let body = json!({"request_id":Uuid::new_v4(),"community_id":c,"pubkey":p});
    let bytes = serde_json::to_vec(&body).unwrap();
    let outage = http
        .post("http://localhost:55443/api/v1/relay/membership/check")
        .header(
            "Authorization",
            auth(
                &service,
                "localhost:55443",
                "/api/v1/relay/membership/check",
                &bytes,
            ),
        )
        .body(bytes)
        .send()
        .await;
    assert!(Command::new("docker")
        .args(["unpause", &container])
        .status()
        .unwrap()
        .success());
    assert!(outage.is_err() || !outage.unwrap().status().is_success());
    drop(process);
    let fallback = launch(&service, None, database_url.as_str(), false);
    ready(&http).await;
    let response = http
        .post("http://localhost:55443/api/v1/relay/membership/check")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let mut anonymous = BuzzTestClient::connect_unauthenticated("ws://localhost:55443")
        .await
        .unwrap();
    anonymous
        .subscribe("anonymous", vec![nostr::Filter::new().limit(1)])
        .await
        .unwrap();
    assert!(anonymous
        .collect_until_eose("anonymous", Duration::from_secs(2))
        .await
        .is_err());
    drop(anonymous);
    drop(fallback);
    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE {name}")))
        .execute(&admin)
        .await
        .unwrap();
    println!("live membership: absent/active/revoked, sticky removal, nonce/signature, auth, receipts, races, restart, outage and read-only checks passed");
}
