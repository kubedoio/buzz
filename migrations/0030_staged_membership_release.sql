ALTER TABLE relay_membership_state
    ADD COLUMN send_enabled BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN staged_operation_id UUID;

CREATE FUNCTION mutate_relay_membership_with_gate(
    c UUID, p TEXT, a TEXT, op UUID, k INTEGER, r TEXT, expected BIGINT, staged BOOLEAN
) RETURNS TABLE(outcome TEXT, revision BIGINT, changed BOOLEAN)
LANGUAGE plpgsql AS $$
DECLARE
    mutation RECORD;
BEGIN
    IF staged AND k <> 9030 THEN RAISE EXCEPTION 'only additions may be staged'; END IF;
    SELECT * INTO mutation FROM mutate_relay_membership(c, p, a, op, k, r, expected);
    outcome := mutation.outcome;
    revision := mutation.revision;
    changed := mutation.changed;
    IF outcome = 'ok' AND changed AND k = 9030 THEN
        UPDATE relay_membership_state
        SET send_enabled = NOT staged,
            staged_operation_id = CASE WHEN staged THEN op ELSE NULL END
        WHERE community_id = c AND pubkey = p;
    END IF;
    RETURN NEXT;
END $$;

CREATE FUNCTION release_relay_membership(
    c UUID, p TEXT, a TEXT, op UUID, staged_op UUID, expected BIGINT
) RETURNS TEXT LANGUAGE plpgsql AS $$
DECLARE
    enabled BOOLEAN;
    actor_role TEXT;
    s relay_membership_state%ROWTYPE;
    prior relay_membership_receipts%ROWTYPE;
    result TEXT := 'ok';
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'membership release requires READ COMMITTED isolation';
    END IF;
    SELECT membership_v1alpha2 INTO enabled FROM communities WHERE id = c FOR UPDATE;
    IF enabled IS DISTINCT FROM true OR p !~ '^[0-9a-f]{64}$' OR a !~ '^[0-9a-f]{64}$'
        OR op = '00000000-0000-0000-0000-000000000000'::uuid
        OR staged_op = '00000000-0000-0000-0000-000000000000'::uuid OR expected < 1 THEN
        RAISE EXCEPTION 'invalid membership release';
    END IF;
    SELECT role INTO actor_role FROM relay_members WHERE community_id = c AND pubkey = a;
    IF actor_role IS NULL OR actor_role NOT IN ('owner', 'admin') THEN
        RAISE EXCEPTION 'actor not authorized';
    END IF;
    IF EXISTS (SELECT 1 FROM community_bans WHERE community_id = c AND pubkey = decode(a, 'hex')
        AND banned AND (ban_expires_at IS NULL OR ban_expires_at > now())) THEN
        RAISE EXCEPTION 'actor banned';
    END IF;
    SELECT * INTO prior FROM relay_membership_receipts WHERE operation_id = op;
    IF FOUND THEN
        IF prior.community_id <> c OR prior.kind <> 9034 OR prior.role <> staged_op::text
            OR prior.pubkey <> p OR prior.actor <> a OR prior.expected_revision <> expected THEN
            RETURN 'operation_conflict';
        END IF;
        RETURN prior.outcome;
    END IF;
    SELECT * INTO s FROM relay_membership_state WHERE community_id = c AND pubkey = p FOR UPDATE;
    IF NOT FOUND OR NOT EXISTS (
        SELECT 1 FROM relay_members WHERE community_id = c AND pubkey = p
    ) THEN
        result := 'not_active';
    ELSIF s.revision <> expected THEN
        result := 'stale_revision';
    ELSIF s.send_enabled OR s.staged_operation_id <> staged_op THEN
        result := 'not_staged';
    ELSIF EXISTS (SELECT 1 FROM community_bans WHERE community_id = c AND pubkey = decode(p, 'hex')
        AND banned AND (ban_expires_at IS NULL OR ban_expires_at > now())) THEN
        result := 'target_banned';
    ELSIF s.revision = 9223372036854775807 THEN
        result := 'revision_overflow';
    ELSE
        UPDATE relay_membership_state
        SET send_enabled = true, staged_operation_id = NULL, revision = revision + 1
        WHERE community_id = c AND pubkey = p;
    END IF;
    INSERT INTO relay_membership_receipts
        VALUES (c, op, p, a, 9034, staged_op::text, expected, result, COALESCE(s.revision, 0));
    RETURN result;
END $$;
