-- Fix PL/pgSQL output-column ambiguity in the encrypted EIN upsert.
-- The function body otherwise intentionally matches the deployed 3.6B version.

create or replace function public.store_business_ein_secret(
    p_actor_user_id uuid,
    p_organization_id uuid,
    p_business_id uuid,
    p_ein_last_four text,
    p_ciphertext text,
    p_iv text,
    p_auth_tag text,
    p_key_version integer
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
    case_id uuid;
    item_id uuid;
    item_created boolean := false;
    previous_item_status public.verification_item_status;
begin
    if p_actor_user_id is null or not exists (
        select 1 from auth.users u where u.id = p_actor_user_id
    ) then
        raise insufficient_privilege using message = 'A valid actor is required.';
    end if;

    if p_ein_last_four is null or p_ein_last_four !~ '^[0-9]{4}$' then
        raise invalid_parameter_value using message = 'Invalid EIN last four.';
    end if;

    if p_ciphertext is null or p_ciphertext = ''
       or p_iv is null or p_iv = ''
       or p_auth_tag is null or p_auth_tag = ''
       or p_key_version is null or p_key_version <= 0 then
        raise invalid_parameter_value using message = 'Invalid encrypted EIN payload.';
    end if;

    if not exists (
        select 1
        from public.organization_members om
        where om.organization_id = p_organization_id
          and om.user_id = p_actor_user_id
          and om.status = 'active'::public.membership_status
          and om.role in (
              'owner'::public.organization_role,
              'admin'::public.organization_role
          )
    ) then
        raise insufficient_privilege using message = 'Organization update permission is required.';
    end if;

    perform 1
    from public.businesses b
    where b.id = p_business_id
      and b.organization_id = p_organization_id
    for update;

    if not found then
        raise no_data_found using message = 'Business not found.';
    end if;

    insert into public.business_ein_secrets (
        business_id,
        ciphertext,
        iv,
        auth_tag,
        key_version
    ) values (
        p_business_id,
        p_ciphertext,
        p_iv,
        p_auth_tag,
        p_key_version
    )
    on conflict on constraint business_ein_secrets_pkey do update
    set ciphertext = excluded.ciphertext,
        iv = excluded.iv,
        auth_tag = excluded.auth_tag,
        key_version = excluded.key_version;

    update public.businesses as b
    set ein_last_four = p_ein_last_four
    where b.id = p_business_id;

    select vc.id
    into case_id
    from public.verification_cases vc
    where vc.organization_id = p_organization_id
      and vc.business_id = p_business_id
      and vc.status in ('draft', 'submitted', 'in_review', 'action_required')
    order by vc.created_at desc
    limit 1
    for update;

    if case_id is null then
        insert into public.verification_cases (
            organization_id,
            business_id,
            status
        ) values (
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
      and vi.item_type = 'ein'::public.verification_item_type
    for update;

    if item_id is null then
        insert into public.verification_items (
            verification_case_id,
            item_type,
            status,
            verification_method
        ) values (
            case_id,
            'ein'::public.verification_item_type,
            'pending'::public.verification_item_status,
            'api'::public.verification_method
        )
        returning id into item_id;

        item_created := true;
    else
        update public.verification_items as vi
        set status = 'pending'::public.verification_item_status,
            verification_method = 'api'::public.verification_method,
            reviewed_by_user_id = null,
            reviewed_at = null,
            rejection_reason = null,
            correction_notes = null
        where vi.id = item_id;
    end if;

    insert into public.verification_item_history (
        verification_item_id,
        previous_status,
        new_status,
        action,
        reason,
        actor_user_id
    ) values (
        item_id,
        case when item_created then null else previous_item_status end,
        'pending'::public.verification_item_status,
        case
            when item_created then 'created'::public.verification_history_action
            else 'status_changed'::public.verification_history_action
        end,
        case
            when item_created then null
            else 'Encrypted EIN intake replaced; prior verification state was invalidated.'
        end,
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
        p_organization_id,
        p_actor_user_id,
        'update'::public.audit_action,
        'business_ein_intake',
        p_business_id,
        jsonb_build_object(
            'verification_case_id', case_id,
            'verification_item_id', item_id,
            'stored_fields', jsonb_build_array('encrypted_ein', 'ein_last_four')
        )
    );

    return query
    select p_business_id, p_ein_last_four, case_id, item_id;
end;
$$;

revoke all on function public.store_business_ein_secret(
    uuid, uuid, uuid, text, text, text, text, integer
) from public, anon, authenticated;

grant execute on function public.store_business_ein_secret(
    uuid, uuid, uuid, text, text, text, text, integer
) to service_role;

comment on function public.store_business_ein_secret(
    uuid, uuid, uuid, text, text, text, text, integer
) is 'Service-role-only encrypted EIN intake with unambiguous primary-key upsert handling.';
