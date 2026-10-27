//! Real PostgreSQL contract tests. No unavailable-database skips.
use buzz_core::CommunityId;
use buzz_db::{relay_members::ConditionalMembership, Db};
use sqlx::PgPool;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires disposable PostgreSQL with database creation permission"]
async fn migration_receipts_concurrency_and_restart() {
    let url = std::env::var("BUZZ_TEST_DATABASE_URL").expect("disposable database URL required");
    let admin = PgPool::connect(&url).await.unwrap();
    let name = format!("membership_{}", Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&admin)
        .await
        .unwrap();
    let mut options: sqlx::postgres::PgConnectOptions = url.parse().unwrap();
    options = options.database(&name);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_with(options.clone())
        .await
        .unwrap();
    let migrator = sqlx::migrate!("../../migrations");
    migrator.run_to(28, &pool).await.unwrap();
    let c = Uuid::new_v4();
    sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
        .bind(c)
        .bind(format!("{c}.test"))
        .execute(&pool)
        .await
        .unwrap();
    let owner = "11".repeat(32);
    let key = "22".repeat(32);
    let historical = "33".repeat(32);
    for p in [&owner, &key, &historical] {
        sqlx::query("INSERT INTO relay_members (community_id, pubkey, role) VALUES ($1,$2,$3)")
            .bind(c)
            .bind(p)
            .bind(if p == &owner { "owner" } else { "member" })
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query("DELETE FROM relay_members WHERE community_id=$1 AND pubkey=$2")
        .bind(c)
        .bind(&historical)
        .execute(&pool)
        .await
        .unwrap();
    migrator.run(&pool).await.unwrap();
    let unreachable_replica = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .unwrap();
    let db = Db::from_pools(pool.clone(), unreachable_replica);
    let community = CommunityId::from_uuid(c);
    assert_eq!(
        db.authoritative_membership(community, &key).await.unwrap(),
        ("active".into(), 1)
    );
    assert_eq!(
        db.authoritative_membership(community, &historical)
            .await
            .unwrap(),
        ("absent".into(), 0)
    );
    sqlx::query("UPDATE communities SET membership_v1alpha2=true WHERE id=$1")
        .bind(c)
        .execute(&pool)
        .await
        .unwrap();
    // Existing owner bootstrap must remain restart-safe.
    db.bootstrap_owner(community, &owner).await.unwrap();
    let operation_id = Uuid::new_v4();
    let mut cmd = ConditionalMembership {
        pubkey: &key,
        actor: &owner,
        operation_id,
        kind: 9031,
        role: "member",
        expected_revision: 1,
    };
    assert_eq!(
        db.conditional_membership(community, &cmd).await.unwrap(),
        ("ok".into(), 2, true)
    );
    assert_eq!(
        db.conditional_membership(community, &cmd).await.unwrap(),
        ("ok".into(), 2, false)
    );
    cmd.kind = 9030;
    assert_eq!(
        db.conditional_membership(community, &cmd).await.unwrap().0,
        "operation_conflict"
    );
    cmd.operation_id = Uuid::new_v4();
    cmd.expected_revision = 2;
    assert_eq!(
        db.conditional_membership(community, &cmd).await.unwrap().0,
        "revoked"
    );
    assert!(db
        .add_relay_member(community, &key, "member", Some(&owner))
        .await
        .is_err());
    assert!(db
        .claim_relay_membership(community, &key, "member", None)
        .await
        .is_err());
    assert!(db.bootstrap_owner(community, &key).await.is_err());
    assert_eq!(
        db.authoritative_membership(community, &key).await.unwrap(),
        ("revoked".into(), 2)
    );
    // Absent removal creates a sticky tombstone; repeated removal is a no-op.
    cmd.pubkey = &historical;
    cmd.kind = 9031;
    cmd.expected_revision = 0;
    cmd.operation_id = Uuid::new_v4();
    assert_eq!(
        db.conditional_membership(community, &cmd).await.unwrap(),
        ("ok".into(), 1, true)
    );
    cmd.expected_revision = 1;
    cmd.operation_id = Uuid::new_v4();
    assert_eq!(
        db.conditional_membership(community, &cmd).await.unwrap(),
        ("ok".into(), 1, false)
    );
    // A stale rejection remains stable after the target advances.
    let racing = "44".repeat(32);
    let add = ConditionalMembership {
        pubkey: &racing,
        actor: &owner,
        operation_id: Uuid::new_v4(),
        kind: 9030,
        role: "member",
        expected_revision: 0,
    };
    let remove = ConditionalMembership {
        operation_id: Uuid::new_v4(),
        kind: 9031,
        ..add
    };
    let (a, b) = tokio::join!(
        db.conditional_membership(community, &add),
        db.conditional_membership(community, &remove)
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert!(matches!(
        (a.0.as_str(), b.0.as_str()),
        ("ok", "stale_revision") | ("stale_revision", "ok")
    ));
    assert_eq!(
        db.authoritative_membership(community, &racing)
            .await
            .unwrap()
            .1,
        1
    );
    let retry = ConditionalMembership {
        operation_id: Uuid::new_v4(),
        expected_revision: 1,
        ..remove
    };
    db.conditional_membership(community, &retry).await.unwrap();
    let replay = db
        .conditional_membership(
            community,
            if a.0 == "stale_revision" {
                &add
            } else {
                &remove
            },
        )
        .await
        .unwrap();
    assert_eq!(replay, ("stale_revision".into(), 1, false));
    assert_eq!(
        db.authoritative_membership(community, &racing)
            .await
            .unwrap()
            .0,
        "revoked"
    );
    // Unauthorized callers do not create receipts or state.
    let denied = ConditionalMembership {
        actor: &historical,
        pubkey: &"55".repeat(32),
        operation_id: Uuid::new_v4(),
        ..add
    };
    assert!(db.conditional_membership(community, &denied).await.is_err());
    assert_eq!(
        db.authoritative_membership(community, denied.pubkey)
            .await
            .unwrap(),
        ("absent".into(), 0)
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM relay_membership_state")
        .fetch_one(&pool)
        .await
        .unwrap();
    for _ in 0..3 {
        db.authoritative_membership(community, denied.pubkey)
            .await
            .unwrap();
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM relay_membership_state")
            .fetch_one(&pool)
            .await
            .unwrap(),
        count
    );
    // Community isolation and v1alpha1 compatibility.
    let other = Uuid::new_v4();
    sqlx::query("INSERT INTO communities (id,host) VALUES ($1,$2)")
        .bind(other)
        .bind(format!("{other}.test"))
        .execute(&pool)
        .await
        .unwrap();
    let other = CommunityId::from_uuid(other);
    db.add_relay_member(other, &key, "member", None)
        .await
        .unwrap();
    db.remove_relay_member(other, &key).await.unwrap();
    db.add_relay_member(other, &key, "member", None)
        .await
        .unwrap();
    assert_eq!(
        db.authoritative_membership(other, &key).await.unwrap(),
        ("active".into(), 3)
    );
    db.bootstrap_owner(other, &owner).await.unwrap();
    sqlx::query("UPDATE communities SET membership_v1alpha2=true WHERE id=$1")
        .bind(other.as_uuid())
        .execute(&pool)
        .await
        .unwrap();
    let foreign = ConditionalMembership {
        pubkey: &key,
        actor: &owner,
        operation_id,
        kind: 9031,
        role: "member",
        expected_revision: 1,
    };
    assert_eq!(
        db.conditional_membership(other, &foreign).await.unwrap().0,
        "operation_conflict"
    );
    assert_eq!(
        db.authoritative_membership(other, &key).await.unwrap(),
        ("active".into(), 3)
    );
    // Re-open all database connections: revisions and receipts remain durable.
    let crash_key = "66".repeat(32);
    let crash_op = Uuid::new_v4();
    let mut transaction = pool.begin().await.unwrap();
    sqlx::query("SELECT * FROM mutate_relay_membership($1,$2,$3,$4,9030,'member',0)")
        .bind(c)
        .bind(&crash_key)
        .bind(&owner)
        .bind(crash_op)
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.rollback().await.unwrap();
    assert_eq!(
        db.authoritative_membership(community, &crash_key)
            .await
            .unwrap(),
        ("absent".into(), 0)
    );
    let receipts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM relay_membership_receipts WHERE operation_id=$1")
            .bind(crash_op)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(receipts, 0);
    let overflow_key = "77".repeat(32);
    let overflow = ConditionalMembership {
        pubkey: &overflow_key,
        operation_id: Uuid::new_v4(),
        ..add
    };
    db.conditional_membership(community, &overflow)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE relay_membership_state SET revision=$3 WHERE community_id=$1 AND pubkey=$2",
    )
    .bind(c)
    .bind(&overflow_key)
    .bind(i64::MAX)
    .execute(&pool)
    .await
    .unwrap();
    let overflow = ConditionalMembership {
        kind: 9031,
        operation_id: Uuid::new_v4(),
        expected_revision: i64::MAX,
        ..overflow
    };
    assert!(db
        .conditional_membership(community, &overflow)
        .await
        .is_err());
    assert_eq!(
        db.authoritative_membership(community, &overflow_key)
            .await
            .unwrap(),
        ("active".into(), i64::MAX)
    );
    drop(db);
    pool.close().await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_with(options)
        .await
        .unwrap();
    let db = Db::from_pool(pool.clone());
    assert_eq!(
        db.authoritative_membership(community, &key).await.unwrap(),
        ("revoked".into(), 2)
    );
    let replay = ConditionalMembership {
        pubkey: &key,
        actor: &owner,
        operation_id,
        kind: 9031,
        role: "member",
        expected_revision: 1,
    };
    assert_eq!(
        db.conditional_membership(community, &replay).await.unwrap(),
        ("ok".into(), 2, false)
    );
    drop(db);
    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE {name}")))
        .execute(&admin)
        .await
        .unwrap();
}
