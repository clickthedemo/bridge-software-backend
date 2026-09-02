-- ============================================================================
-- BRIDGE — MILESTONE 3.5
-- Atomic organization onboarding and scoped organization updates
-- ============================================================================

create or replace function public.create_organization_with_owner(
    p_name text,
    p_organization_type public.organization_type
)
returns table (
    organization_id uuid,
    organization_name text,
    organization_type public.organization_type,
    membership_role public.organization_role,
    membership_status public.membership_status
)
language plpgsql
security definer
set search_path = ''
as $$
declare
    authenticated_user_id uuid := auth.uid();
    created_organization_id uuid;
    normalized_name text := nullif(btrim(p_name), '');
begin
    if authenticated_user_id is null then
        raise insufficient_privilege using
            message = 'Authentication is required.';
    end if;

    if normalized_name is null or p_organization_type is null then
        raise invalid_parameter_value using
            message = 'Organization name and type are required.';
    end if;

    insert into public.organizations as organization (
        name,
        organization_type
    )
    values (
        normalized_name,
        p_organization_type
    )
    returning organization.id into created_organization_id;

    insert into public.organization_members (
        organization_id,
        user_id,
        role,
        status
    )
    values (
        created_organization_id,
        authenticated_user_id,
        'owner'::public.organization_role,
        'active'::public.membership_status
    );

    return query
    select
        created_organization_id,
        normalized_name,
        p_organization_type,
        'owner'::public.organization_role,
        'active'::public.membership_status;
end;
$$;

revoke all on function public.create_organization_with_owner(
    text,
    public.organization_type
) from public;
revoke all on function public.create_organization_with_owner(
    text,
    public.organization_type
) from anon;
revoke all on function public.create_organization_with_owner(
    text,
    public.organization_type
) from authenticated;
grant execute on function public.create_organization_with_owner(
    text,
    public.organization_type
) to authenticated;

create policy organizations_update_admin
on public.organizations
for update
to authenticated
using (
    public.is_organization_admin(id)
)
with check (
    public.is_organization_admin(id)
);

-- RLS scopes the row; column privileges ensure normal clients can only change
-- fields supported by the Milestone 3.5 organization update contract.
revoke update on public.organizations from authenticated;
grant update (name, organization_type) on public.organizations to authenticated;

comment on function public.create_organization_with_owner(
    text,
    public.organization_type
) is
    'Atomically create an organization and active owner membership for auth.uid().';
