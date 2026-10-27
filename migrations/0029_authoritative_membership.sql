-- Opt-in only. Enable under an exclusive relay_members lock after draining all
-- legacy admission workers. Existing v1alpha1 communities keep their semantics.
ALTER TABLE communities ADD COLUMN membership_v1alpha2 BOOLEAN NOT NULL DEFAULT false;

LOCK TABLE relay_members IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE relay_membership_state (
    community_id UUID NOT NULL REFERENCES communities(id),
    pubkey TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision >= 0),
    revoked BOOLEAN NOT NULL,
    PRIMARY KEY (community_id, pubkey)
);
INSERT INTO relay_membership_state
    SELECT community_id, pubkey, 1, false FROM relay_members;
-- Previously deleted keys cannot be reconstructed from event history.

CREATE TABLE relay_membership_receipts (
    community_id UUID NOT NULL REFERENCES communities(id),
    operation_id UUID NOT NULL,
    pubkey TEXT NOT NULL,
    actor TEXT NOT NULL,
    kind INTEGER NOT NULL,
    role TEXT NOT NULL,
    expected_revision BIGINT NOT NULL,
    outcome TEXT NOT NULL,
    revision BIGINT NOT NULL,
    PRIMARY KEY (operation_id)
);
-- UUID replay protection spans communities; receipt access remains community-authorized.
INSERT INTO _operator_global_tables (table_name, reason) VALUES
    ('relay_membership_receipts', 'deployment-wide operation UUID replay registry; receipts remain bound to the authorized community, actor and exact command');

-- Cover invites, operator tools, startup, ownership transfer and future writers.
-- An AFTER trigger also covers ON CONFLICT paths without rejecting a harmless
-- bootstrap of the existing owner on restart. DB access remains a trusted boundary.
CREATE FUNCTION guard_relay_membership() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    c UUID;
    p TEXT;
    enabled BOOLEAN;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF OLD.community_id <> NEW.community_id OR OLD.pubkey <> NEW.pubkey THEN
            RAISE EXCEPTION 'membership identity is immutable';
        END IF;
        IF OLD.role = NEW.role THEN RETURN NULL; END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN c := OLD.community_id; p := OLD.pubkey;
    ELSE c := NEW.community_id; p := NEW.pubkey; END IF;
    SELECT membership_v1alpha2 INTO enabled FROM communities WHERE id = c FOR UPDATE;
    IF enabled AND current_setting('buzz.membership_operation', true) IS DISTINCT FROM 'conditional' THEN
        RAISE EXCEPTION 'v1alpha2 requires a conditional membership operation';
    END IF;
    IF TG_OP = 'UPDATE' THEN RETURN NULL; END IF;
    INSERT INTO relay_membership_state (community_id, pubkey, revision, revoked)
        VALUES (c, p, 1, TG_OP = 'DELETE')
        ON CONFLICT (community_id, pubkey) DO UPDATE
        SET revision = relay_membership_state.revision + 1,
            revoked = EXCLUDED.revoked;
    RETURN NULL;
END $$;
CREATE TRIGGER relay_membership_guard AFTER INSERT OR UPDATE OR DELETE ON relay_members
    FOR EACH ROW EXECUTE FUNCTION guard_relay_membership();

-- shortcut: serialize per community; use ordered actor/target locks if throughput requires it.
-- Community serialization also makes actor-role validation and operation-ID
-- conflicts atomic across different target keys. Receipts are never pruned.
CREATE FUNCTION mutate_relay_membership(
    c UUID, p TEXT, a TEXT, op UUID, k INTEGER, r TEXT, expected BIGINT
) RETURNS TABLE(outcome TEXT, revision BIGINT, changed BOOLEAN)
LANGUAGE plpgsql AS $$
DECLARE
    enabled BOOLEAN;
    actor_role TEXT;
    target_role TEXT;
    prior relay_membership_receipts%ROWTYPE;
    s relay_membership_state%ROWTYPE;
    result TEXT := 'ok';
    did_change BOOLEAN := false;
BEGIN
    -- Authorization and receipts must use a fresh snapshot after the community lock.
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'conditional membership requires READ COMMITTED isolation';
    END IF;
    SELECT membership_v1alpha2 INTO enabled FROM communities WHERE id = c FOR UPDATE;
    IF enabled IS DISTINCT FROM true THEN RAISE EXCEPTION 'v1alpha2 not enabled'; END IF;
    IF p !~ '^[0-9a-f]{64}$' OR a !~ '^[0-9a-f]{64}$'
        OR k NOT IN (9030, 9031) OR r NOT IN ('member', 'admin') OR expected < 0
        OR op = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'invalid conditional membership operation';
    END IF;
    SELECT role INTO actor_role FROM relay_members WHERE community_id = c AND pubkey = a;
    IF actor_role IS NULL OR actor_role NOT IN ('owner', 'admin') THEN
        RAISE EXCEPTION 'actor not authorized';
    END IF;
    IF EXISTS (SELECT 1 FROM community_bans WHERE community_id = c AND pubkey = decode(a, 'hex')
        AND banned AND (ban_expires_at IS NULL OR ban_expires_at > now())) THEN
        RAISE EXCEPTION 'actor banned';
    END IF;
    SELECT role INTO target_role FROM relay_members WHERE community_id = c AND pubkey = p;
    IF (k = 9030 AND r = 'admin' AND actor_role <> 'owner')
        OR (k = 9031 AND (p = a OR target_role = 'owner'
            OR (actor_role = 'admin' AND target_role IS NOT NULL AND target_role <> 'member'))) THEN
        RAISE EXCEPTION 'actor not authorized for target role';
    END IF;
    SELECT * INTO prior FROM relay_membership_receipts WHERE operation_id = op;
    IF FOUND THEN
        IF prior.community_id <> c OR prior.pubkey <> p OR prior.actor <> a OR prior.kind <> k OR prior.role <> r
            OR prior.expected_revision <> expected THEN
            RETURN QUERY SELECT 'operation_conflict'::text, prior.revision, false; RETURN;
        END IF;
        RETURN QUERY SELECT prior.outcome, prior.revision, false; RETURN;
    END IF;
    INSERT INTO relay_membership_state VALUES (c, p, 0, false) ON CONFLICT DO NOTHING;
    SELECT * INTO s FROM relay_membership_state WHERE community_id = c AND pubkey = p FOR UPDATE;
    SELECT role INTO target_role FROM relay_members WHERE community_id = c AND pubkey = p;
    IF s.revision <> expected THEN result := 'stale_revision';
    ELSIF k = 9030 AND s.revoked THEN result := 'revoked';
    ELSE
        PERFORM set_config('buzz.membership_operation', 'conditional', true);
        IF k = 9030 AND target_role IS NULL THEN
            INSERT INTO relay_members (community_id, pubkey, role, added_by) VALUES (c, p, r, a);
            did_change := true;
        ELSIF k = 9031 AND target_role IS NOT NULL THEN
            DELETE FROM relay_members WHERE community_id = c AND pubkey = p;
            did_change := true;
        ELSIF k = 9031 AND NOT s.revoked THEN
            UPDATE relay_membership_state SET revoked = true,
                revision = relay_membership_state.revision + 1 WHERE community_id = c AND pubkey = p;
            did_change := true;
        END IF;
        PERFORM set_config('buzz.membership_operation', '', true);
    END IF;
    SELECT * INTO s FROM relay_membership_state WHERE community_id = c AND pubkey = p;
    INSERT INTO relay_membership_receipts VALUES (c, op, p, a, k, r, expected, result, s.revision);
    RETURN QUERY SELECT result, s.revision, did_change;
END $$;
