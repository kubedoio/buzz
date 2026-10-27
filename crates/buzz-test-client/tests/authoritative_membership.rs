//! Launches the actual relay binary against disposable PostgreSQL and Redis.
//! Build buzz-relay first; all infrastructure settings must be explicit.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use nostr::{Event, EventBuilder, JsonUtil, Keys, Kind, Tag};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};
use uuid::Uuid;

struct Relay(Child);
impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn launch(service: &Keys, relay: &Keys, database_url: &str) -> Relay {
    let log = std::fs::File::create(std::env::temp_dir().join("membership-conformance-relay.log"))
        .unwrap();
    Relay(
        Command::new(std::env::var("BUZZ_TEST_RELAY_BINARY").expect("build buzz-relay first"))
            .env("DATABASE_URL", database_url)
            .env("REDIS_URL", std::env::var("BUZZ_TEST_REDIS_URL").unwrap())
            .env("RELAY_URL", "ws://localhost:55443")
            .env("BUZZ_BIND_ADDR", "127.0.0.1:55443")
            .env("BUZZ_HEALTH_PORT", "55444")
            .env("BUZZ_METRICS_PORT", "55445")
            .env("BUZZ_AUTO_MIGRATE", "true")
            .env("BUZZ_GIT_ENABLED", "false")
            .env("BUZZ_RELAY_PRIVATE_KEY", relay.secret_key().to_secret_hex())
            .env("RELAY_OWNER_PUBKEY", service.public_key().to_hex())
            .env(
                "RELAY_TRUSTED_SERVICE_PUBKEYS",
                service.public_key().to_hex(),
            )
            .env("BUZZ_REQUIRE_AUTH_TOKEN", "true")
            .env("BUZZ_REQUIRE_RELAY_MEMBERSHIP", "false")
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
    let tags = [
        vec!["p".into(), p.into()],
        vec!["elembra-op".into(), op.to_string()],
        vec!["elembra-expected-revision".into(), revision.to_string()],
    ]
    .into_iter()
    .map(|t| Tag::parse(t).unwrap());
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

#[tokio::test]
#[ignore = "requires disposable PostgreSQL/Redis, Docker, and built relay binary"]
async fn live_membership_contract() {
    let mut database_url =
        url::Url::parse(&std::env::var("BUZZ_TEST_DATABASE_URL").unwrap()).unwrap();
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
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let mut process = launch(&service, &relay, database_url.as_str());
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
    let p = Keys::generate().public_key().to_hex();
    let initial = read(&http, &service, &relay, c, &p).await;
    assert_eq!(initial["membership"], "absent");
    assert_eq!(initial["membership_revision"], 0);
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
    assert!(mutate(&http, &service, &p, 9031, Uuid::new_v4(), 1).await);
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
    let before:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM relay_members),(SELECT count(*) FROM relay_membership_state),(SELECT count(*) FROM relay_membership_receipts)").fetch_one(&pool).await.unwrap();
    read(
        &http,
        &service,
        &relay,
        c,
        &Keys::generate().public_key().to_hex(),
    )
    .await;
    let after:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM relay_members),(SELECT count(*) FROM relay_membership_state),(SELECT count(*) FROM relay_membership_receipts)").fetch_one(&pool).await.unwrap();
    assert_eq!(before, after);
    drop(process);
    process = launch(&service, &relay, database_url.as_str());
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
    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE {name}")))
        .execute(&admin)
        .await
        .unwrap();
    println!("live membership: absent/active/revoked, sticky removal, nonce/signature, auth, receipts, races, restart, outage and read-only checks passed");
}
