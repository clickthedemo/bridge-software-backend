-- ============================================================================
-- BRIDGE — MILESTONE 3.7
-- Platform-admin verification queue, safe detail projection, and review action
-- ============================================================================

create or replace function public.list_admin_verification_queue(
    p_actor_user_id uuid,
    p_status public.verification_item_status default null,
    p_item_type public.verification_item_type default null,
    p_organization_id uuid default null,
    p_limit integer default 50
)
returns table (
    verification_case_id uuid,
    verification_item_id uuid,
    organization_id uuid,
    organization_name text,
    business_id uuid,
    business_legal_name text,
    item_type public.verification_item_type,
    item_status public.verification_item_status,
    verification_method public.verification_method,
    case_created_at timestamptz,
    case_submitted_at timestamptz,
    item_created_at timestamptz,
    item_updated_at timestamptz,
    item_reviewed_at timestamptz
)
language plpgsql
security definer
set search_path = ''
as $$
begin
    if p_actor_user_id is null or not exists (
        select 1 from auth.users u where u.id = p_actor_user_id
    ) then
        raise insufficient_privilege using message = 'A valid actor is required.';
    end if;

    if not exists (
        select 1
        from public.user_platform_roles upr
        where upr.user_id = p_actor_user_id
          and upr.role = 'admin'::public.platform_role
    ) then
        raise insufficient_privilege using message = 'Platform administrator permission is required.';
    end if;

    if p_limit is null or p_limit < 1 or p_limit > 100 then
        raise invalid_parameter_value using message = 'Queue limit must be between 1 and 100.';
    end if;

    return query
    select
        vc.id,
        vi.id,
        o.id,
        o.name,
        b.id,
        b.legal_name,
        vi.item_type,
        vi.status,
        vi.verification_method,
        vc.created_at,
        vc.submitted_at,
        vi.created_at,
        vi.updated_at,
        vi.reviewed_at
    from public.verification_items vi
    join public.verification_cases vc on vc.id = vi.verification_case_id
    join public.organizations o on o.id = vc.organization_id
    join public.businesses b
      on b.id = vc.business_id
     and b.organization_id = vc.organization_id
    where (
        (p_status is null and vi.status in (
            'pending'::public.verification_item_status,
            'in_review'::public.verification_item_status,
            'verification_requested'::public.verification_item_status,
            'correction_required'::public.verification_item_status
        ))
        or vi.status = p_status
    )
      and (p_item_type is null or vi.item_type = p_item_type)
      and (p_organization_id is null or vc.organization_id = p_organization_id)
    order by vi.updated_at asc, vi.id asc
    limit p_limit;
end;
$$;

create or replace function public.get_admin_verification_case(
    p_actor_user_id uuid,
    p_verification_case_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    result jsonb;
begin
    if p_actor_user_id is null or not exists (
        select 1 from auth.users u where u.id = p_actor_user_id
    ) then
        raise insufficient_privilege using message = 'A valid actor is required.';
    end if;

    if not exists (
        select 1
        from public.user_platform_roles upr
        where upr.user_id = p_actor_user_id
          and upr.role = 'admin'::public.platform_role
    ) then
        raise insufficient_privilege using message = 'Platform administrator permission is required.';
    end if;

    select jsonb_build_object(
        'verification_case_id', vc.id,
        'status', vc.status,
        'submitted_at', vc.submitted_at,
        'started_review_at', vc.started_review_at,
        'completed_at', vc.completed_at,
        'created_at', vc.created_at,
        'updated_at', vc.updated_at,
        'organization', jsonb_build_object(
            'id', o.id,
            'name', o.name,
            'organization_type', o.organization_type
        ),
        'business', jsonb_build_object(
            'id', b.id,
            'legal_name', b.legal_name,
            'dba_name', b.dba_name,
            'ein_last_four', b.ein_last_four,
            'cannabis_license_number', b.cannabis_license_number,
            'cannabis_license_state', b.cannabis_license_state
        ),
        'items', coalesce((
            select jsonb_agg(
                jsonb_build_object(
                    'id', vi.id,
                    'item_type', vi.item_type,
                    'status', vi.status,
                    'verification_method', vi.verification_method,
                    'reviewed_by_user_id', vi.reviewed_by_user_id,
                    'reviewed_at', vi.reviewed_at,
                    'rejection_reason', vi.rejection_reason,
                    'correction_notes', vi.correction_notes,
                    'created_at', vi.created_at,
                    'updated_at', vi.updated_at,
                    'history', coalesce((
                        select jsonb_agg(
                            jsonb_build_object(
                                'id', vih.id,
                                'previous_status', vih.previous_status,
                                'new_status', vih.new_status,
                                'action', vih.action,
                                'reason', vih.reason,
                                'notes', vih.notes,
                                'actor_user_id', vih.actor_user_id,
                                'created_at', vih.created_at
                            ) order by vih.created_at asc, vih.id asc
                        )
                        from public.verification_item_history vih
                        where vih.verification_item_id = vi.id
                    ), '[]'::jsonb),
                    'documents', coalesce((
                        select jsonb_agg(
                            jsonb_build_object(
                                'id', d.id,
                                'document_type', d.document_type,
                                'file_name', d.file_name,
                                'mime_type', d.mime_type,
                                'file_size_bytes', d.file_size_bytes,
                                'uploaded_by_user_id', d.uploaded_by_user_id,
                                'uploaded_at', d.uploaded_at,
                                'review_status', d.review_status,
                                'reviewed_by_user_id', d.reviewed_by_user_id,
                                'reviewed_at', d.reviewed_at,
                                'review_notes', d.review_notes
                            ) order by d.uploaded_at asc, d.id asc
                        )
                        from public.verification_item_documents vid
                        join public.documents d on d.id = vid.document_id
                        where vid.verification_item_id = vi.id
                    ), '[]'::jsonb),
                    'ein_verification_attempts', coalesce((
                        select jsonb_agg(
                            jsonb_build_object(
                                'id', ev.id,
                                'provider', ev.provider,
                                'provider_reference', ev.provider_reference,
                                'result_status', ev.result_status,
                                'result_reason', ev.result_reason,
                                'requested_at', ev.requested_at,
                                'completed_at', ev.completed_at
                            ) order by ev.requested_at asc, ev.id asc
                        )
                        from public.ein_verifications ev
                        where ev.verification_item_id = vi.id
                    ), '[]'::jsonb),
                    'cannabis_license_verifications', coalesce((
                        select jsonb_agg(
                            jsonb_build_object(
                                'id', clv.id,
                                'state_code', clv.state_code,
                                'license_number', clv.license_number,
                                'registry_name', clv.registry_name,
                                'registry_url', clv.registry_url,
                                'looked_up_by_user_id', clv.looked_up_by_user_id,
                                'looked_up_at', clv.looked_up_at,
                                'result_status', clv.result_status,
                                'result_notes', clv.result_notes
                            ) order by clv.looked_up_at asc, clv.id asc
                        )
                        from public.cannabis_license_verifications clv
                        where clv.verification_item_id = vi.id
                    ), '[]'::jsonb)
                ) order by vi.created_at asc, vi.id asc
            )
            from public.verification_items vi
            where vi.verification_case_id = vc.id
        ), '[]'::jsonb)
    )
    into result
    from public.verification_cases vc
    join public.organizations o on o.id = vc.organization_id
    join public.businesses b
      on b.id = vc.business_id
     and b.organization_id = vc.organization_id
    where vc.id = p_verification_case_id;

    if result is null then
        raise no_data_found using message = 'Verification case not found.';
    end if;

    return result;
end;
$$;

create or replace function public.review_admin_verification_item(
    p_actor_user_id uuid,
    p_verification_item_id uuid,
    p_decision public.verification_item_status,
    p_reason text default null
)
returns table (
    verification_item_id uuid,
    verification_case_id uuid,
    organization_id uuid,
    previous_status public.verification_item_status,
    new_status public.verification_item_status,
    reviewed_by_user_id uuid,
    reviewed_at timestamptz
)
language plpgsql
security definer
set search_path = ''
as $$
declare
    target_case_id uuid;
    target_organization_id uuid;
    prior_status public.verification_item_status;
    review_time timestamptz := timezone('utc', now());
    history_action public.verification_history_action;
    audit_action public.audit_action;
    normalized_reason text := nullif(btrim(p_reason), '');
begin
    if p_actor_user_id is null or not exists (
        select 1 from auth.users u where u.id = p_actor_user_id
    ) then
        raise insufficient_privilege using message = 'A valid actor is required.';
    end if;

    if not exists (
        select 1
        from public.user_platform_roles upr
        where upr.user_id = p_actor_user_id
          and upr.role = 'admin'::public.platform_role
    ) then
        raise insufficient_privilege using message = 'Platform administrator permission is required.';
    end if;

    if p_decision is null or p_decision not in (
        'verified'::public.verification_item_status,
        'rejected'::public.verification_item_status,
        'correction_required'::public.verification_item_status
    ) then
        raise invalid_parameter_value using message = 'Invalid review decision.';
    end if;

    if p_decision in (
        'rejected'::public.verification_item_status,
        'correction_required'::public.verification_item_status
    ) and normalized_reason is null then
        raise invalid_parameter_value using message = 'A reason is required for this review decision.';
    end if;

    select vi.verification_case_id, vc.organization_id, vi.status
    into target_case_id, target_organization_id, prior_status
    from public.verification_items vi
    join public.verification_cases vc on vc.id = vi.verification_case_id
    where vi.id = p_verification_item_id
    for update of vi;

    if target_case_id is null then
        raise no_data_found using message = 'Verification item not found.';
    end if;

    if prior_status not in (
        'pending'::public.verification_item_status,
        'in_review'::public.verification_item_status,
        'verification_requested'::public.verification_item_status,
        'correction_required'::public.verification_item_status,
        'rejected'::public.verification_item_status
    ) or prior_status = p_decision then
        raise object_not_in_prerequisite_state using
            message = 'Verification item cannot transition from its current status.';
    end if;

    history_action := case p_decision
        when 'verified'::public.verification_item_status
            then 'approved'::public.verification_history_action
        when 'rejected'::public.verification_item_status
            then 'rejected'::public.verification_history_action
        else 'correction_requested'::public.verification_history_action
    end;

    audit_action := case p_decision
        when 'verified'::public.verification_item_status
            then 'approve'::public.audit_action
        when 'rejected'::public.verification_item_status
            then 'reject'::public.audit_action
        else 'request_correction'::public.audit_action
    end;

    update public.verification_items as vi
    set status = p_decision,
        reviewed_by_user_id = p_actor_user_id,
        reviewed_at = review_time,
        rejection_reason = case
            when p_decision = 'rejected'::public.verification_item_status
                then normalized_reason
            else null
        end,
        correction_notes = case
            when p_decision = 'correction_required'::public.verification_item_status
                then normalized_reason
            else null
        end
    where vi.id = p_verification_item_id;

    insert into public.verification_item_history (
        verification_item_id,
        previous_status,
        new_status,
        action,
        reason,
        actor_user_id
    ) values (
        p_verification_item_id,
        prior_status,
        p_decision,
        history_action,
        normalized_reason,
        p_actor_user_id
    );

    insert into public.audit_logs (
        organization_id,
        actor_user_id,
        action,
        entity_type,
        entity_id,
        metadata
    ) values (
        target_organization_id,
        p_actor_user_id,
        audit_action,
        'verification_item',
        p_verification_item_id,
        jsonb_build_object(
            'verification_case_id', target_case_id,
            'previous_status', prior_status,
            'new_status', p_decision
        )
    );

    return query
    select
        p_verification_item_id,
        target_case_id,
        target_organization_id,
        prior_status,
        p_decision,
        p_actor_user_id,
        review_time;
end;
$$;

revoke all on function public.list_admin_verification_queue(
    uuid, public.verification_item_status, public.verification_item_type, uuid, integer
) from public, anon, authenticated;
grant execute on function public.list_admin_verification_queue(
    uuid, public.verification_item_status, public.verification_item_type, uuid, integer
) to service_role;

revoke all on function public.get_admin_verification_case(uuid, uuid)
from public, anon, authenticated;
grant execute on function public.get_admin_verification_case(uuid, uuid)
to service_role;

revoke all on function public.review_admin_verification_item(
    uuid, uuid, public.verification_item_status, text
) from public, anon, authenticated;
grant execute on function public.review_admin_verification_item(
    uuid, uuid, public.verification_item_status, text
) to service_role;

comment on function public.list_admin_verification_queue(
    uuid, public.verification_item_status, public.verification_item_type, uuid, integer
) is 'Service-role-only platform-admin queue with a database-enforced safe projection.';
comment on function public.get_admin_verification_case(uuid, uuid) is
    'Service-role-only platform-admin case detail projection excluding encrypted EIN and provider raw responses.';
comment on function public.review_admin_verification_item(
    uuid, uuid, public.verification_item_status, text
) is 'Service-role-only atomic platform-admin item review with immutable history and audit records.';
