-- ============================================================================
-- BRIDGE — MILESTONE 3.6
-- EIN intake and admin-triggered verification workflow
-- ============================================================================

create or replace function public.intake_business_ein(
    p_organization_id uuid,
    p_business_id uuid,
    p_ein_last_four text
)
returns table (
    business_id uuid,
    ein_last_four text,
    verification_case_id uuid,
    verification_item_id uuid
)
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor_id uuid := auth.uid();
    case_id uuid;
    item_id uuid;
    item_created boolean := false;
    previous_ein_last_four text;
    previous_item_status public.verification_item_status;
begin
    if actor_id is null then
        raise insufficient_privilege using message = 'Authentication is required.';
    end if;

    if p_ein_last_four is null or p_ein_last_four !~ '^[0-9]{4}$' then
        raise invalid_parameter_value using message = 'Invalid EIN last four.';
    end if;

    if not public.is_organization_admin(p_organization_id) then
        raise insufficient_privilege using message = 'Organization update permission is required.';
    end if;

    select b.ein_last_four
    into previous_ein_last_four
    from public.businesses b
    where b.id = p_business_id
      and b.organization_id = p_organization_id
    for update;

    if not found then
        raise no_data_found using message = 'Business not found.';
    end if;

    update public.businesses
    set ein_last_four = p_ein_last_four
    where id = p_business_id
      and organization_id = p_organization_id;

    select vc.id
    into case_id
    from public.verification_cases vc
    where vc.organization_id = p_organization_id
      and vc.business_id = p_business_id
      and vc.status in ('draft', 'submitted', 'in_review', 'action_required')
    order by vc.created_at desc
    limit 1;

    if case_id is null then
        insert into public.verification_cases (
            organization_id,
            business_id,
            status
        )
        values (
            p_organization_id,
            p_business_id,
            'draft'::public.verification_case_status
        )
        returning id into case_id;
    end if;

    select vi.id, vi.status
    into item_id, previous_item_status
    from public.verification_items vi
    where vi.verification_case_id = case_id
      and vi.item_type = 'ein'::public.verification_item_type;

    if item_id is null then
        insert into public.verification_items (
            verification_case_id,
            item_type,
            status,
            verification_method
        )
        values (
            case_id,
            'ein'::public.verification_item_type,
            'pending'::public.verification_item_status,
            'api'::public.verification_method
        )
        returning id into item_id;

        item_created := true;
    end if;

    if item_created then
        insert into public.verification_item_history (
            verification_item_id,
            previous_status,
            new_status,
            action,
            actor_user_id
        )
        values (
            item_id,
            null,
            'pending'::public.verification_item_status,
            'created'::public.verification_history_action,
            actor_id
        );
    elsif previous_ein_last_four is distinct from p_ein_last_four then
        update public.verification_items
        set status = 'pending'::public.verification_item_status,
            verification_method = 'api'::public.verification_method,
            reviewed_by_user_id = null,
            reviewed_at = null,
            rejection_reason = null,
            correction_notes = null
        where id = item_id;

        insert into public.verification_item_history (
            verification_item_id,
            previous_status,
            new_status,
            action,
            reason,
            actor_user_id
        )
        values (
            item_id,
            previous_item_status,
            'pending'::public.verification_item_status,
            'status_changed'::public.verification_history_action,
            'EIN intake changed; prior verification state was invalidated.',
            actor_id
        );
    end if;

    insert into public.audit_logs (
        organization_id,
        actor_user_id,
        action,
        entity_type,
        entity_id,
        metadata
    )
    values (
        p_organization_id,
        actor_id,
        'update'::public.audit_action,
        'business_ein_intake',
        p_business_id,
        jsonb_build_object(
            'verification_case_id', case_id,
            'verification_item_id', item_id,
            'stored_fields', jsonb_build_array('ein_last_four')
        )
    );

    return query
    select p_business_id, p_ein_last_four, case_id, item_id;
end;
$$;

create or replace function public.request_ein_verification(
    p_verification_item_id uuid,
    p_ein_last_four text,
    p_provider text
)
returns table (
    ein_verification_id uuid,
    organization_id uuid,
    business_id uuid,
    legal_name text,
    verification_item_id uuid
)
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor_id uuid := auth.uid();
    target_organization_id uuid;
    target_business_id uuid;
    target_legal_name text;
    stored_ein_last_four text;
    previous_item_status public.verification_item_status;
    attempt_id uuid;
    is_platform_admin boolean;
begin
    if actor_id is null then
        raise insufficient_privilege using message = 'Authentication is required.';
    end if;

    select exists (
        select 1
        from public.user_platform_roles upr
        where upr.user_id = actor_id
          and upr.role = 'admin'::public.platform_role
    ) into is_platform_admin;

    select
        vc.organization_id,
        vc.business_id,
        b.legal_name,
        b.ein_last_four,
        vi.status
    into
        target_organization_id,
        target_business_id,
        target_legal_name,
        stored_ein_last_four,
        previous_item_status
    from public.verification_items vi
    join public.verification_cases vc on vc.id = vi.verification_case_id
    join public.businesses b on b.id = vc.business_id
    where vi.id = p_verification_item_id
      and vi.item_type = 'ein'::public.verification_item_type
      and b.organization_id = vc.organization_id;

    if target_organization_id is null then
        raise no_data_found using message = 'EIN verification item not found.';
    end if;

    if not is_platform_admin
       and not public.is_organization_reviewer(target_organization_id) then
        raise insufficient_privilege using message = 'Verification review permission is required.';
    end if;

    -- API verification may start from a new/reviewable item or explicitly
    -- restart after a rejected/correction-required result. It must not silently
    -- overwrite verified, not-applicable, or already-requested state.
    if previous_item_status not in (
        'pending',
        'in_review',
        'rejected',
        'correction_required'
    ) then
        raise object_not_in_prerequisite_state using
            message = 'EIN verification cannot start from the current item status.';
    end if;

    if p_ein_last_four is null
       or stored_ein_last_four is null
       or stored_ein_last_four <> p_ein_last_four then
        raise invalid_parameter_value using message = 'EIN does not match intake data.';
    end if;

    insert into public.ein_verifications (
        verification_item_id,
        provider,
        requested_by_user_id,
        result_status
    )
    values (
        p_verification_item_id,
        p_provider,
        actor_id,
        'requested'
    )
    returning id into attempt_id;

    update public.verification_items
    set status = 'verification_requested'::public.verification_item_status,
        verification_method = 'api'::public.verification_method
    where id = p_verification_item_id;

    insert into public.verification_item_history (
        verification_item_id,
        previous_status,
        new_status,
        action,
        actor_user_id
    )
    values (
        p_verification_item_id,
        previous_item_status,
        'verification_requested'::public.verification_item_status,
        'verification_requested'::public.verification_history_action,
        actor_id
    );

    insert into public.audit_logs (
        organization_id,
        actor_user_id,
        action,
        entity_type,
        entity_id,
        metadata
    )
    values (
        target_organization_id,
        actor_id,
        'verification_requested'::public.audit_action,
        'ein_verification',
        attempt_id,
        jsonb_build_object(
            'verification_item_id', p_verification_item_id,
            'provider', p_provider
        )
    );

    return query
    select
        attempt_id,
        target_organization_id,
        target_business_id,
        target_legal_name,
        p_verification_item_id;
end;
$$;

create or replace function public.complete_ein_verification(
    p_ein_verification_id uuid,
    p_provider_reference text,
    p_result_status text,
    p_result_reason text,
    p_item_status public.verification_item_status
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor_id uuid;
    target_organization_id uuid;
    target_item_id uuid;
    previous_item_status public.verification_item_status;
begin
    if p_item_status is null or p_item_status not in (
        'verification_requested',
        'verified',
        'rejected',
        'correction_required'
    ) then
        raise invalid_parameter_value using message = 'Invalid completion status.';
    end if;

    select
        vc.organization_id,
        vi.id,
        vi.status,
        ev.requested_by_user_id
    into
        target_organization_id,
        target_item_id,
        previous_item_status,
        actor_id
    from public.ein_verifications ev
    join public.verification_items vi on vi.id = ev.verification_item_id
    join public.verification_cases vc on vc.id = vi.verification_case_id
    where ev.id = p_ein_verification_id
    for update of ev, vi;

    if target_item_id is null then
        raise no_data_found using message = 'EIN verification attempt not found.';
    end if;

    if exists (
        select 1
        from public.ein_verifications ev
        where ev.id = p_ein_verification_id
          and ev.completed_at is not null
    ) then
        raise object_not_in_prerequisite_state using
            message = 'EIN verification attempt is already complete.';
    end if;

    update public.ein_verifications
    set provider_reference = p_provider_reference,
        completed_at = timezone('utc', now()),
        result_status = p_result_status,
        result_reason = p_result_reason
    where id = p_ein_verification_id;

    update public.verification_items
    set status = p_item_status,
        reviewed_by_user_id = case
            when p_item_status = 'verification_requested' then reviewed_by_user_id
            else actor_id
        end,
        reviewed_at = case
            when p_item_status = 'verification_requested' then reviewed_at
            else timezone('utc', now())
        end,
        rejection_reason = case when p_item_status = 'rejected' then p_result_reason else null end,
        correction_notes = case when p_item_status = 'correction_required' then p_result_reason else null end
    where id = target_item_id;

    insert into public.verification_item_history (
        verification_item_id,
        previous_status,
        new_status,
        action,
        reason,
        actor_user_id
    )
    values (
        target_item_id,
        previous_item_status,
        p_item_status,
        'verification_completed'::public.verification_history_action,
        p_result_reason,
        actor_id
    );

    insert into public.audit_logs (
        organization_id,
        actor_user_id,
        action,
        entity_type,
        entity_id,
        metadata
    )
    values (
        target_organization_id,
        actor_id,
        'verification_completed'::public.audit_action,
        'ein_verification',
        p_ein_verification_id,
        jsonb_build_object(
            'verification_item_id', target_item_id,
            'result_status', p_result_status
        )
    );
end;
$$;

revoke all on function public.intake_business_ein(uuid, uuid, text) from public, anon, authenticated;
grant execute on function public.intake_business_ein(uuid, uuid, text) to authenticated;

revoke all on function public.request_ein_verification(uuid, text, text) from public, anon, authenticated;
grant execute on function public.request_ein_verification(uuid, text, text) to authenticated;

revoke all on function public.complete_ein_verification(uuid, text, text, text, public.verification_item_status) from public, anon, authenticated;
grant execute on function public.complete_ein_verification(uuid, text, text, text, public.verification_item_status) to service_role;

comment on function public.intake_business_ein(uuid, uuid, text) is
    'Persist EIN last four, ensure an active case/EIN item, and append history/audit records.';
comment on function public.request_ein_verification(uuid, text, text) is
    'Authorize and record an admin-triggered EIN provider request without receiving the full EIN.';
comment on function public.complete_ein_verification(uuid, text, text, text, public.verification_item_status) is
    'Backend-only provider completion using actor attribution from the locked verification attempt.';
